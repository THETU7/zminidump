//! 源码嵌入:按导出选项查找调用栈引用的源码。
//!
//! 查找顺序:本地绝对路径(DWARF 记录路径,通常已按 `DW_AT_comp_dir`
//! 拼接为绝对路径)→ 各 debuginfod 的 `/source/{buildid}/{path}`。
//! 同一源码文件只下载一次;`context` 模式合并重叠片段;总大小受上限
//! 约束,超限时停止嵌入并记录省略。

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
    ) -> Self {
        Self {
            resolver,
            mode,
            context_lines,
            max_bytes,
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

        // 聚合同一文件的引用。
        let mut files: Vec<(String, FileRef)> = Vec::new();
        let mut index_of: HashMap<String, usize> = HashMap::new();
        for (path, build_id, lines) in references {
            let idx = match index_of.get(&path) {
                Some(i) => *i,
                None => {
                    files.push((
                        path.clone(),
                        FileRef {
                            lines: Vec::new(),
                            build_id,
                        },
                    ));
                    index_of.insert(path, files.len() - 1);
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
                    let (ranges, selected) = match self.mode {
                        SourceMode::Full => {
                            let sel = all_lines.clone();
                            let n = sel.len().max(1) as u32;
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

    /// 获取源码内容:本地路径 → 源码缓存 → debuginfod。
    async fn fetch_file(&self, path: &str, build_id: Option<&str>) -> Result<String, SourceStatus> {
        // 1. 本地绝对路径直接可用(开发机常见)。
        let local = PathBuf::from(path);
        if local.is_file() {
            if let Ok(text) = std::fs::read_to_string(&local) {
                return Ok(text);
            }
            // 以丢失容错方式读取非 UTF-8 源文件。
            if let Ok(bytes) = std::fs::read(&local) {
                return Ok(String::from_utf8_lossy(&bytes).into_owned());
            }
        }

        let Some(build_id) = build_id else {
            return Err(SourceStatus::NotFound);
        };
        let cfg = self.resolver.config();

        // 2. 各服务器缓存。
        for server in &cfg.debuginfod_urls {
            let cache = self.resolver.source_cache_path(server, build_id, path);
            if let Ok(text) = std::fs::read_to_string(&cache) {
                return Ok(text);
            }
        }

        // 3. debuginfod /source。
        if cfg.debuginfod_urls.is_empty() {
            return Err(SourceStatus::NotFound);
        }
        let mut last_not_archived = false;
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
                    last_not_archived = true;
                    continue;
                }
                Ok(FetchResult::Failed(message)) => {
                    return Err(SourceStatus::FetchFailed { message });
                }
                Err(e) => {
                    return Err(SourceStatus::FetchFailed {
                        message: format!("下载任务失败:{e}"),
                    });
                }
            }
        }
        if last_not_archived {
            Err(SourceStatus::NotArchived)
        } else {
            Err(SourceStatus::NotFound)
        }
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
pub fn merge_ranges<I: IntoIterator<Item = u32>>(
    lines: I,
    context: u32,
    total: u32,
) -> Vec<(u32, u32)> {
    let mut wanted: Vec<u32> = lines.into_iter().filter(|l| *l >= 1).collect();
    wanted.sort_unstable();
    wanted.dedup();
    if wanted.is_empty() {
        return Vec::new();
    }
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    let total = total.max(1);
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
mod tests {
    use super::*;
    use crate::artifacts::{ArtifactResolver, ResolverConfig};
    use crate::report::{Report, SourceStatus};

    fn collector(mode: SourceMode, max_bytes: u64) -> (SourceCollector, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("zmsrc-{}-{}", std::process::id(), mode.as_str()));
        std::fs::create_dir_all(&dir).unwrap();
        let resolver = std::sync::Arc::new(ArtifactResolver::new(ResolverConfig {
            cache_dir: dir.join("cache"),
            ..Default::default()
        }));
        (SourceCollector::new(resolver, mode, 1, max_bytes), dir)
    }

    async fn embed(mode: SourceMode, max_bytes: u64) -> (Report, std::path::PathBuf) {
        let (collector, dir) = collector(mode, max_bytes);
        let file_a = dir.join("a.c");
        let file_b = dir.join("b.c");
        std::fs::write(
            &file_a,
            (1..=50)
                .map(|i| format!("line-{i:02}\n"))
                .collect::<String>(),
        )
        .unwrap();
        std::fs::write(
            &file_b,
            (1..=50).map(|i| format!("B-{i:02}\n")).collect::<String>(),
        )
        .unwrap();
        let mut report = Report {
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
            source_mode: mode,
            source_omitted_count: 0,
            source_max_bytes: max_bytes,
        };
        let refs = vec![
            (
                file_a.to_string_lossy().into_owned(),
                None,
                vec![10u32, 11, 30],
            ),
            (file_b.to_string_lossy().into_owned(), None, vec![5]),
        ];
        collector.embed(&mut report, refs).await;
        (report, dir)
    }

    #[tokio::test]
    async fn context_mode_merges_and_caps() {
        let (report, dir) = embed(SourceMode::Context, 60).await;
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
        let (report, dir) = embed(SourceMode::Full, 10_000).await;
        let src = &report.sources[0];
        assert!(matches!(src.status, SourceStatus::Embedded { .. }));
        assert_eq!(src.lines.as_ref().unwrap().len(), 50);
        assert_eq!(src.line_ranges.as_ref().unwrap(), &vec![(1, 50)]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn none_mode_records_disabled_only() {
        let (report, dir) = embed(SourceMode::None, 10_000).await;
        assert!(
            report
                .sources
                .iter()
                .all(|s| matches!(s.status, SourceStatus::Disabled))
        );
        assert!(report.sources.iter().all(|s| s.lines.is_none()));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn merge_ranges_merges_overlap_and_clamps() {
        // 10 ±2 与 11 ±2 合并为 8..=13;120 超出总行数时收敛到末尾。
        let ranges = merge_ranges(vec![10, 11, 100], 2, 50);
        assert_eq!(ranges, vec![(8, 13), (48, 50)]);
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
