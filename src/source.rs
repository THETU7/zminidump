//! 源码嵌入:按导出选项查找调用栈引用的源码。
//!
//! 优先使用按 Build ID 查到的归档源码(各 debuginfod 的
//! `/buildid/{buildid}/source/{path}` 及其缓存),保证内容与报告中的
//! 构建一致。本机路径仅在用户显式配置源码根目录(`--source-root`)时
//! 读取,且解析后的路径必须仍位于某个根目录内。同一源码路径可能来自
//! 不同构建,报告全程以 (Build ID, 路径) 为键区分。同一文件只下载
//! 一次;`context` 模式合并重叠片段;总大小受上限约束,超限时停止
//! 嵌入并记录省略。

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use crate::{
    artifacts::{ArtifactResolver, hex_lower},
    debuginfod::FetchResult,
    report::{Report, SourceFileReport, SourceMode, SourceStatus},
};

/// 源码收集器。
pub struct SourceCollector {
    resolver: Arc<ArtifactResolver>,
    mode: SourceMode,
    context_lines: u32,
    max_bytes: u64,
    /// 用户显式授权的本地源码根目录;为空时不读取任何本机文件。
    source_roots: Vec<PathBuf>,
}

/// 一个被引用的源码文件的聚合信息。
#[derive(Debug, Default, Clone)]
struct FileRef {
    /// 引用的行号集合(context 模式围绕这些行取样)。
    lines: Vec<u32>,
    /// 提供该文件的模块 Build ID。
    build_id: Option<String>,
}

impl SourceCollector {
    pub fn new(
        resolver: Arc<ArtifactResolver>,
        mode: SourceMode,
        context_lines: u32,
        max_bytes: u64,
        source_roots: Vec<PathBuf>,
    ) -> Self {
        Self {
            resolver,
            mode,
            context_lines,
            max_bytes,
            source_roots,
        }
    }

    /// 为报告嵌入源码并回填帧锚点。
    /// `priority` 为文件引用顺序(崩溃线程在前,保证预算优先用于关键帧)。
    pub async fn embed(
        &self,
        report: &mut Report,
        references: Vec<(String, Option<String>, Vec<u32>)>, // (path, build_id, lines)
    ) {
        if self.mode == SourceMode::None {
            // 只记录状态,不获取内容。
            let mut seen: Vec<(String, Option<String>)> = Vec::new();
            for (path, build_id, _) in &references {
                let key = (path.clone(), build_id.clone());
                if !seen.contains(&key) {
                    seen.push(key);
                }
            }
            for (path, build_id) in seen {
                report.sources.push(SourceFileReport {
                    index: report.sources.len(),
                    path,
                    build_id,
                    status: SourceStatus::Disabled,
                    lines: None,
                    line_ranges: None,
                });
            }
            return;
        }

        // 聚合引用;同一路径可能由不同构建引用,以 (路径, Build ID) 为键,
        // 不同构建的同名源码文件分别嵌入。
        let mut files: Vec<(String, FileRef)> = Vec::new();
        let mut index_of: HashMap<(String, Option<String>), usize> = HashMap::new();
        for (path, build_id, lines) in references {
            let key = (path.clone(), build_id.clone());
            let idx = match index_of.get(&key) {
                Some(i) => *i,
                None => {
                    files.push((
                        path.clone(),
                        FileRef {
                            lines: Vec::new(),
                            build_id,
                        },
                    ));
                    index_of.insert(key, files.len() - 1);
                    files.len() - 1
                }
            };
            files[idx].1.lines.extend(lines);
        }

        let mut budget = self.max_bytes;
        let mut omitted = 0usize;
        for (path, file_ref) in files {
            if budget == 0 {
                omitted += 1;
                report.sources.push(SourceFileReport {
                    index: report.sources.len(),
                    path,
                    build_id: file_ref.build_id,
                    status: SourceStatus::SizeCapped,
                    lines: None,
                    line_ranges: None,
                });
                continue;
            }

            let fetched = self.fetch_file(&path, file_ref.build_id.as_deref()).await;
            match fetched {
                Ok(content) => {
                    let all_lines = split_lines(&content);
                    // 空文件没有第 1 行:嵌入零行内容,不生成任何区间,
                    // 锚点回填也会跳过(避免指向不存在的行)。
                    let (ranges, selected) = if all_lines.is_empty() {
                        (Vec::new(), Vec::new())
                    } else {
                        match self.mode {
                            SourceMode::Full => {
                                let sel = all_lines.clone();
                                let n = sel.len() as u32;
                                (vec![(1, n)], sel)
                            }
                            _ => {
                                let ranges = merge_ranges(
                                    file_ref.lines.iter().copied(),
                                    self.context_lines,
                                    all_lines.len() as u32,
                                );
                                let sel = ranges
                                    .iter()
                                    .flat_map(|(a, b)| {
                                        all_lines[(*a as usize - 1)..(*b as usize)].to_vec()
                                    })
                                    .collect();
                                (ranges, sel)
                            }
                        }
                    };
                    let bytes: usize = selected.iter().map(|l| l.len() + 1).sum();
                    if bytes as u64 > budget {
                        omitted += 1;
                        report.sources.push(SourceFileReport {
                            index: report.sources.len(),
                            path,
                            build_id: file_ref.build_id,
                            status: SourceStatus::SizeCapped,
                            lines: None,
                            line_ranges: None,
                        });
                        continue;
                    }
                    budget -= bytes as u64;
                    report.sources.push(SourceFileReport {
                        index: report.sources.len(),
                        path,
                        build_id: file_ref.build_id,
                        status: SourceStatus::Embedded { bytes },
                        lines: Some(selected),
                        line_ranges: Some(ranges),
                    });
                }
                Err(status) => {
                    report.sources.push(SourceFileReport {
                        index: report.sources.len(),
                        path,
                        build_id: file_ref.build_id,
                        status,
                        lines: None,
                        line_ranges: None,
                    });
                }
            }
        }
        report.source_omitted_count = omitted;
    }

    /// 获取源码内容:按 Build ID 的归档缓存 → debuginfod `/source` →
    /// 用户显式授权的本地源码根目录。默认(未配置根目录)绝不读取
    /// 本机文件,避免把与报告构建无关的内容嵌入报告。
    ///
    /// 单个服务出错(网络、5xx 等)不中断查找:保留诊断后继续尝试其余
    /// 服务与本地目录;所有来源都失败时才报告获取错误。
    async fn fetch_file(&self, path: &str, build_id: Option<&str>) -> Result<String, SourceStatus> {
        let mut not_archived = false;
        let mut last_error: Option<SourceStatus> = None;

        // 1. 按 Build ID 查找:各服务器缓存 → debuginfod /source。
        if let Some(build_id) = build_id {
            let cfg = self.resolver.config();

            for server in &cfg.debuginfod_urls {
                let cache = self.resolver.source_cache_path(server, build_id, path);
                if let Ok(text) = std::fs::read_to_string(&cache) {
                    return Ok(text);
                }
            }

            for server in &cfg.debuginfod_urls {
                let permit = self
                    .resolver
                    .semaphore()
                    .clone()
                    .acquire_owned()
                    .await
                    .unwrap();
                let client = self.resolver.client().clone();
                let url = server.clone();
                let bid = build_id.to_string();
                let p = path.to_string();
                let result =
                    tokio::task::spawn_blocking(move || client.fetch_source(&url, &bid, &p)).await;
                drop(permit);
                match result {
                    Ok(FetchResult::Ok(bytes)) => {
                        let text = String::from_utf8_lossy(&bytes).into_owned();
                        let cache = self.resolver.source_cache_path(server, build_id, path);
                        crate::artifacts::write_atomic(&cache, text.as_bytes()).ok();
                        return Ok(text);
                    }
                    Ok(FetchResult::NotFound) => {
                        not_archived = true;
                    }
                    Ok(FetchResult::Failed(message)) => {
                        last_error = Some(SourceStatus::FetchFailed {
                            message: format!("({server}):{message}"),
                        });
                    }
                    Err(e) => {
                        last_error = Some(SourceStatus::FetchFailed {
                            message: format!("({server}):下载任务失败:{e}"),
                        });
                    }
                }
            }
        }

        // 2. 用户显式授权的本地源码根目录;解析后的路径必须仍位于根内。
        //    归档中未找到或服务出错时,本地获准的源码仍可离线嵌入。
        if let Some(text) = self.read_local_authorized(path) {
            return Ok(text);
        }

        Err(match last_error {
            // 服务出错的诊断保留到最后;未归档次之。
            Some(e) => e,
            None if not_archived => SourceStatus::NotArchived,
            None => SourceStatus::NotFound,
        })
    }

    /// 读取本机源码文件;仅当用户显式配置了源码根目录,且路径规范化后
    /// 仍位于某个根目录之内时允许。符号链接逃逸会被两侧的 canonicalize
    /// 规整后排除。
    fn read_local_authorized(&self, path: &str) -> Option<String> {
        if self.source_roots.is_empty() {
            return None;
        }
        let local = PathBuf::from(path);
        let canonical = local.canonicalize().ok()?;
        for root in &self.source_roots {
            let Ok(root_canonical) = root.canonicalize() else {
                continue;
            };
            if canonical.starts_with(&root_canonical) {
                if let Ok(text) = std::fs::read_to_string(&canonical) {
                    return Some(text);
                }
                // 以丢失容错方式读取非 UTF-8 源文件。
                if let Ok(bytes) = std::fs::read(&canonical) {
                    return Some(String::from_utf8_lossy(&bytes).into_owned());
                }
            }
        }
        None
    }
}

fn split_lines(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = text
        .split('\n')
        .map(|s| s.trim_end_matches('\r').to_string())
        .collect();
    if lines.last().map(|s| s.is_empty()).unwrap_or(false) {
        lines.pop();
    }
    lines
}

/// 合并行号 ±context 的重叠区间,输出 1 起始的闭区间列表(有序)。
/// 文件没有内容(`total == 0`)时返回空:不存在可嵌入的行。
pub fn merge_ranges<I: IntoIterator<Item = u32>>(
    lines: I,
    context: u32,
    total: u32,
) -> Vec<(u32, u32)> {
    let mut wanted: Vec<u32> = lines.into_iter().filter(|l| *l >= 1).collect();
    wanted.sort_unstable();
    wanted.dedup();
    if wanted.is_empty() || total == 0 {
        return Vec::new();
    }
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for line in wanted {
        let line = line.min(total);
        let start = line.saturating_sub(context).max(1);
        let end = line.saturating_add(context).min(total);
        match ranges.last_mut() {
            Some(last) if start <= last.1.saturating_add(1) => {
                last.1 = last.1.max(end);
            }
            _ => ranges.push((start, end)),
        }
    }
    ranges
}

/// 未使用的导入占位(hex_lower 供测试复用)。
#[allow(dead_code)]
fn _keep(v: &[u8]) -> String {
    hex_lower(v)
}

#[cfg(test)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::{ArtifactResolver, ResolverConfig};
    use crate::report::SourceStatus;
    use std::path::Path;

    fn make_collector(
        tag: &str,
        mode: SourceMode,
        max_bytes: u64,
        source_roots: Vec<PathBuf>,
    ) -> (SourceCollector, PathBuf) {
        let dir = std::env::temp_dir().join(format!("zmsrc-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let resolver = Arc::new(ArtifactResolver::new(ResolverConfig {
            cache_dir: dir.join("cache"),
            ..Default::default()
        }));
        (
            SourceCollector::new(resolver, mode, 1, max_bytes, source_roots),
            dir,
        )
    }

    fn empty_report(mode: SourceMode, max_bytes: u64) -> Report {
        Report {
            schema_version: 1,
            tool_name: "t".into(),
            tool_version: "0".into(),
            dump_path: "x.dmp".into(),
            crash_time: None,
            process_id: None,
            exception: None,
            crashing_thread: None,
            system: crate::report::SystemReport {
                os: "Linux".into(),
                cpu: "x86_64".into(),
                cpu_info: None,
                os_version: None,
            },
            threads: vec![],
            modules: vec![],
            sources: vec![],
            notes: Vec::new(),
            source_mode: mode,
            source_omitted_count: 0,
            source_max_bytes: max_bytes,
        }
    }

    fn write_fixture_sources(dir: &Path) {
        std::fs::write(
            dir.join("a.c"),
            (1..=50)
                .map(|i| format!("line-{i:02}\n"))
                .collect::<String>(),
        )
        .unwrap();
        std::fs::write(
            dir.join("b.c"),
            (1..=50).map(|i| format!("B-{i:02}\n")).collect::<String>(),
        )
        .unwrap();
    }

    /// 本地读取需要显式授权的常规嵌入用例:固件目录同时配置为源码根目录。
    fn authorized_collector(mode: SourceMode, max_bytes: u64) -> (SourceCollector, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "zmsrc-embed-{}-{}",
            std::process::id(),
            mode.as_str()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        write_fixture_sources(&dir);
        let resolver = Arc::new(ArtifactResolver::new(ResolverConfig {
            cache_dir: dir.join("cache"),
            ..Default::default()
        }));
        (
            SourceCollector::new(resolver, mode, 1, max_bytes, vec![dir.clone()]),
            dir,
        )
    }

    #[tokio::test]
    async fn context_mode_merges_and_caps() {
        let (collector, dir) = authorized_collector(SourceMode::Context, 60);
        let mut report = empty_report(SourceMode::Context, 60);
        let refs = vec![
            (
                dir.join("a.c").to_string_lossy().into_owned(),
                None,
                vec![10u32, 11, 30],
            ),
            (
                dir.join("b.c").to_string_lossy().into_owned(),
                None,
                vec![5],
            ),
        ];
        collector.embed(&mut report, refs).await;
        // a.c 两段片段 56 字节嵌入后,剩余预算 4 字节 < b.c 的 15 字节 → b.c 被省略。
        let statuses: Vec<&SourceStatus> = report.sources.iter().map(|s| &s.status).collect();
        assert!(
            matches!(statuses[0], SourceStatus::Embedded { .. }),
            "{statuses:?}"
        );
        assert!(
            matches!(statuses[1], SourceStatus::SizeCapped),
            "{statuses:?}"
        );
        assert_eq!(report.source_omitted_count, 1);
        let src = &report.sources[0];
        let ranges = src.line_ranges.as_ref().unwrap();
        assert!(
            ranges.contains(&(9, 12)) && ranges.contains(&(29, 31)),
            "{ranges:?}"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn full_mode_embeds_whole_file() {
        let (collector, dir) = authorized_collector(SourceMode::Full, 10_000);
        let mut report = empty_report(SourceMode::Full, 10_000);
        let refs = vec![(
            dir.join("a.c").to_string_lossy().into_owned(),
            None,
            vec![10u32, 11, 30],
        )];
        collector.embed(&mut report, refs).await;
        let src = &report.sources[0];
        assert!(matches!(src.status, SourceStatus::Embedded { .. }));
        assert_eq!(src.lines.as_ref().unwrap().len(), 50);
        assert_eq!(src.line_ranges.as_ref().unwrap(), &vec![(1, 50)]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn none_mode_records_disabled_only() {
        let (collector, dir) = authorized_collector(SourceMode::None, 10_000);
        let mut report = empty_report(SourceMode::None, 10_000);
        let refs = vec![(
            dir.join("a.c").to_string_lossy().into_owned(),
            None,
            vec![5u32],
        )];
        collector.embed(&mut report, refs).await;
        assert!(
            report
                .sources
                .iter()
                .all(|s| matches!(s.status, SourceStatus::Disabled))
        );
        assert!(report.sources.iter().all(|s| s.lines.is_none()));
        std::fs::remove_dir_all(dir).ok();
    }

    /// P1-4:默认(未配置源码根目录)不得读取本机文件,即使路径真实存在;
    /// 配置包含该文件的根目录后才允许离线嵌入;根目录之外的路径仍被拒绝。
    #[tokio::test]
    async fn local_read_requires_authorized_source_root() {
        let file_dir = std::env::temp_dir().join(format!("zmsrc-auth-file-{}", std::process::id()));
        std::fs::create_dir_all(&file_dir).unwrap();
        let src = file_dir.join("secret.c");
        std::fs::write(&src, "int leak(void) { return 1; }\n").unwrap();
        let path = src.to_string_lossy().into_owned();

        // 1. 默认:未配置源码根目录 → 即使本机存在该文件也不嵌入。
        let (collector, dir) = make_collector("auth-def", SourceMode::Full, 10_000, Vec::new());
        let mut report = empty_report(SourceMode::Full, 10_000);
        collector
            .embed(&mut report, vec![(path.clone(), None, vec![1u32])])
            .await;
        assert_eq!(report.sources.len(), 1);
        assert!(
            matches!(report.sources[0].status, SourceStatus::NotFound),
            "默认不得读取本机文件:{:?}",
            report.sources[0].status
        );
        assert!(report.sources[0].lines.is_none());
        std::fs::remove_dir_all(dir).ok();

        // 2. 显式授权包含该文件的根目录 → 嵌入。
        let (collector, dir) =
            make_collector("auth-ok", SourceMode::Full, 10_000, vec![file_dir.clone()]);
        let mut report = empty_report(SourceMode::Full, 10_000);
        collector
            .embed(&mut report, vec![(path.clone(), None, vec![1u32])])
            .await;
        assert!(matches!(
            report.sources[0].status,
            SourceStatus::Embedded { .. }
        ));
        assert!(
            report.sources[0]
                .lines
                .as_ref()
                .unwrap()
                .iter()
                .any(|l| l.contains("int leak")),
            "获准的本地源码应可离线嵌入"
        );
        std::fs::remove_dir_all(dir).ok();

        // 3. 授权的根目录不包含该路径(位于根外)→ 拒绝。
        let other_root =
            std::env::temp_dir().join(format!("zmsrc-auth-other-{}", std::process::id()));
        std::fs::create_dir_all(&other_root).unwrap();
        let (collector, dir) = make_collector(
            "auth-out",
            SourceMode::Full,
            10_000,
            vec![other_root.clone()],
        );
        let mut report = empty_report(SourceMode::Full, 10_000);
        collector
            .embed(&mut report, vec![(path, None, vec![1u32])])
            .await;
        assert!(
            !matches!(report.sources[0].status, SourceStatus::Embedded { .. }),
            "根目录外的路径不得嵌入:{:?}",
            report.sources[0].status
        );
        std::fs::remove_dir_all(dir).ok();
        std::fs::remove_dir_all(other_root).ok();
        std::fs::remove_dir_all(file_dir).ok();
    }

    /// P2-7:同一路径由两个不同构建引用时分别嵌入,内容互不覆盖。
    /// 两个构建的源码通过按 Build ID 组织的源码缓存提供。
    #[tokio::test]
    async fn same_path_different_builds_embed_separately() {
        let dir = std::env::temp_dir().join(format!("zmsrc-twobuild-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = "/src/shared/version.c";

        // 为两个 Build ID 预置内容不同的源码缓存。
        let server = "http://127.0.0.1:9";
        let resolver = Arc::new(ArtifactResolver::new(ResolverConfig {
            cache_dir: dir.join("cache"),
            debuginfod_urls: vec![server.to_string()],
            ..Default::default()
        }));
        let bid_a = "aa112233445566778899aabbccddeeff0011";
        let bid_b = "bb112233445566778899aabbccddeeff0022";
        let cache_a = resolver.source_cache_path(server, bid_a, path);
        let cache_b = resolver.source_cache_path(server, bid_b, path);
        for (cache, content) in [
            (&cache_a, "int version(void) { return 1; } // build A\n"),
            (&cache_b, "int version(void) { return 2; } // build B\n"),
        ] {
            std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
            std::fs::write(cache, content).unwrap();
        }

        let collector = SourceCollector::new(resolver, SourceMode::Full, 1, 10_000, Vec::new());
        let mut report = empty_report(SourceMode::Full, 10_000);
        collector
            .embed(
                &mut report,
                vec![
                    (path.to_string(), Some(bid_a.to_string()), vec![1u32]),
                    (path.to_string(), Some(bid_b.to_string()), vec![1u32]),
                ],
            )
            .await;

        assert_eq!(report.sources.len(), 2, "两个构建应分别嵌入");
        let a = &report.sources[0];
        let b = &report.sources[1];
        assert_eq!(a.build_id.as_deref(), Some(bid_a));
        assert_eq!(b.build_id.as_deref(), Some(bid_b));
        assert_eq!(a.path, path);
        assert_eq!(b.path, path);
        assert!(matches!(a.status, SourceStatus::Embedded { .. }));
        assert!(matches!(b.status, SourceStatus::Embedded { .. }));
        assert!(
            a.lines.as_ref().unwrap()[0].contains("return 1"),
            "构建 A 的帧应看到版本 1:{}",
            a.lines.as_ref().unwrap()[0]
        );
        assert!(
            b.lines.as_ref().unwrap()[0].contains("return 2"),
            "构建 B 的帧应看到版本 2:{}",
            b.lines.as_ref().unwrap()[0]
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn merge_ranges_merges_overlap_and_clamps() {
        // 10 ±2 与 11 ±2 合并为 8..=13;120 超出总行数时收敛到末尾。
        let ranges = merge_ranges(vec![10, 11, 100], 2, 50);
        assert_eq!(ranges, vec![(8, 13), (48, 50)]);
    }

    /// R2-P1:空文件(成功返回 200/读到 0 字节)不得使 context 模式
    /// 中断:嵌入零行内容,保留有意义的源码状态。
    #[tokio::test]
    async fn empty_source_embeds_zero_lines_without_panic() {
        let file_dir = std::env::temp_dir().join(format!("zmsrc-empty-{}", std::process::id()));
        std::fs::create_dir_all(&file_dir).unwrap();
        let empty = file_dir.join("empty.c");
        std::fs::write(&empty, "").unwrap();

        let (collector, dir) =
            make_collector("empty", SourceMode::Context, 10_000, vec![file_dir.clone()]);
        let mut report = empty_report(SourceMode::Context, 10_000);
        collector
            .embed(
                &mut report,
                vec![(
                    empty.to_string_lossy().into_owned(),
                    None,
                    vec![10u32], // 引用行号超出空文件的实际行数。
                )],
            )
            .await;

        assert_eq!(report.sources.len(), 1);
        let src = &report.sources[0];
        assert!(
            matches!(src.status, SourceStatus::Embedded { bytes: 0 }),
            "空文件应正常嵌入(0 字节):{:?}",
            src.status
        );
        assert_eq!(src.lines.as_deref(), Some(&[][..]));
        assert_eq!(src.line_ranges.as_deref(), Some(&[][..]));
        std::fs::remove_dir_all(dir).ok();
        std::fs::remove_dir_all(file_dir).ok();
    }

    #[test]
    fn merge_ranges_empty_total_is_empty() {
        assert!(merge_ranges(vec![10], 3, 0).is_empty());
    }

    #[test]
    fn merge_ranges_empty() {
        assert!(merge_ranges(Vec::<u32>::new(), 3, 10).is_empty());
    }

    #[test]
    fn split_lines_handles_crlf_and_trailing() {
        assert_eq!(split_lines("a\r\nb\n"), vec!["a", "b"]);
        assert_eq!(split_lines("x"), vec!["x"]);
    }
}
