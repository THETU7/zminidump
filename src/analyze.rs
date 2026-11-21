//! 分析编排:读取 dump → 展开栈 → 生成版本化报告 → 导出。

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use breakpad_symbols::Symbolizer;
use minidump::{Minidump, Module};
use minidump_processor::{ProcessState, process_minidump};
use minidump_unwind::{CallStackInfo, FrameTrust};

use crate::{
    artifacts::{ArtifactResolver, ResolverConfig},
    report::*,
    source::SourceCollector,
    symbols::ArtifactSymbolSupplier,
};

/// 分析选项。
#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    pub symbol_paths: Vec<PathBuf>,
    pub user_binary: Option<PathBuf>,
    pub user_debug_file: Option<PathBuf>,
    pub debuginfod_urls: Vec<String>,
    pub cache_dir: PathBuf,
    pub source_mode: SourceMode,
    /// 用户显式授权的本地源码根目录(`--source-root`);为空时不读取
    /// 任何本机源码文件,源码只来自按 Build ID 查到的归档。
    pub source_roots: Vec<PathBuf>,
    /// `--include-source=context` 时关键帧前后嵌入的行数。
    pub context_lines: u32,
    /// 嵌入源码总大小上限(字节)。
    pub max_source_bytes: u64,
    pub limits: crate::artifacts::Limits,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        Self {
            symbol_paths: Vec::new(),
            user_binary: None,
            user_debug_file: None,
            debuginfod_urls: Vec::new(),
            cache_dir: default_cache_dir(),
            source_mode: SourceMode::Context,
            source_roots: Vec::new(),
            context_lines: 3,
            max_source_bytes: 2 * 1024 * 1024,
            limits: Default::default(),
        }
    }
}

/// 默认缓存目录:`$XDG_CACHE_HOME/zminidump` 或 `~/.cache/zminidump`。
pub fn default_cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME")
        && !dir.is_empty()
    {
        return PathBuf::from(dir).join("zminidump");
    }
    if let Some(home) = std::env::var_os("HOME")
        && !home.is_empty()
    {
        return PathBuf::from(home).join(".cache").join("zminidump");
    }
    std::env::temp_dir().join("zminidump-cache")
}

/// 从 `DEBUGINFOD_URLS` 环境变量读取默认服务器列表。
/// 按 elfutils 约定跳过 `ima:` 前缀的策略指令(如 `ima:enforcing`),
/// 它们不是服务器 URL;当作 URL 请求会以协议错误失败并污染错误信息。
pub fn debuginfod_urls_from_env() -> Vec<String> {
    std::env::var("DEBUGINFOD_URLS")
        .unwrap_or_default()
        .split_whitespace()
        .filter(|s| !s.is_empty() && !s.starts_with("ima:"))
        .map(|s| s.to_string())
        .collect()
}

/// 分析一个 dump,返回版本化报告。
pub async fn analyze_dump(dump_path: &Path, opts: &AnalyzeOptions) -> anyhow_like::Result<Report> {
    let resolver = Arc::new(ArtifactResolver::new(ResolverConfig {
        symbol_paths: opts.symbol_paths.clone(),
        user_binary: opts.user_binary.clone(),
        user_debug_file: opts.user_debug_file.clone(),
        debuginfod_urls: opts.debuginfod_urls.clone(),
        cache_dir: opts.cache_dir.clone(),
        limits: opts.limits.clone(),
    }));

    let dump = Minidump::read_path(dump_path)
        .map_err(|e| format!("读取 dump {} 失败:{e}", dump_path.display()))?;

    let supplier = ArtifactSymbolSupplier::new(resolver.clone());
    let symbolizer = Symbolizer::new(supplier);
    let state = process_minidump(&dump, &symbolizer)
        .await
        .map_err(|e| format!("处理 dump 失败:{e}"))?;

    let mut report = build_report(dump_path, &state, &resolver).await;

    // 源码嵌入:崩溃线程引用在前,保证预算优先用于关键帧。
    let references = collect_source_references(&mut report);
    let collector = SourceCollector::new(
        resolver.clone(),
        opts.source_mode,
        opts.context_lines,
        opts.max_source_bytes,
        opts.source_roots.clone(),
    );
    collector.embed(&mut report, references).await;
    backfill_anchors(&mut report);

    report.source_mode = opts.source_mode;
    report.source_max_bytes = opts.max_source_bytes;
    Ok(report)
}

type BoxErr = Box<dyn std::error::Error + Send + Sync>;
pub mod anyhow_like {
    /// 简单的 boxed error 别名,避免引入 anyhow。
    pub type Result<T> = std::result::Result<T, super::BoxErr>;
}

async fn build_report(
    dump_path: &Path,
    state: &ProcessState,
    resolver: &ArtifactResolver,
) -> Report {
    // 模块表:按展开时使用的模块列表顺序建立基址索引。
    let mut module_index: HashMap<u64, usize> = HashMap::new();
    let mut modules: Vec<ModuleReport> = Vec::new();
    for module in state.modules.iter() {
        let ident = crate::artifacts::ModuleIdentity::from_module(module);
        let artifacts = resolver.finalize_module(&ident);
        let index = modules.len();
        module_index.insert(module.base_address(), index);
        modules.push(ModuleReport {
            index,
            name: crate::util::basename(&module.code_file()),
            code_file: module.code_file().to_string(),
            debug_file: module.debug_file().map(|f| f.to_string()),
            base_address: format!("{:#x}", module.base_address()),
            size: module.size(),
            debug_id: module.debug_identifier().map(|d| format!("{d}")),
            // dump 只有截短标识时,用匹配产物核验出的完整 Build ID。
            build_id: artifacts
                .resolved_build_id
                .clone()
                .or_else(|| ident.full_build_id()),
            code_id: module.code_identifier().map(|c| c.as_str().to_string()),
            version: module.version().map(|v| v.to_string()),
            executable: artifacts.executable.unwrap_or(ArtifactStatus::NoSource),
            debuginfo: artifacts.debuginfo.unwrap_or(ArtifactStatus::NoSource),
            symbols: artifacts.symbols.unwrap_or(SymbolStatus::Missing {
                reason: "该模块未被调用栈引用".into(),
            }),
        });
    }

    // 异常信息。
    let exception = state.exception_info.as_ref().map(|info| ExceptionReport {
        reason: format!("{}", info.reason),
        address: format!("{:#x}", u64::from(info.address)),
        thread_id: state
            .requesting_thread
            .and_then(|i| state.threads.get(i))
            .map(|t| t.thread_id)
            .unwrap_or(0),
    });

    // 线程:崩溃线程置顶,其余按原顺序。
    let mut thread_order: Vec<usize> = (0..state.threads.len()).collect();
    let crashing_report_index = state.requesting_thread.map(|c| {
        if let Some(pos) = thread_order.iter().position(|i| *i == c) {
            thread_order.remove(pos);
            thread_order.insert(0, c);
        }
        0
    });

    let mut threads = Vec::new();
    let mut display_index = 0usize;
    let mut crashing_registers: Option<std::collections::BTreeMap<String, String>> = None;
    for &ti in &thread_order {
        let stack = &state.threads[ti];
        let mut frames = Vec::new();
        for frame in &stack.frames {
            let module_idx = frame
                .module
                .as_ref()
                .and_then(|m| module_index.get(&m.base_address()).copied());
            let offset = frame
                .module
                .as_ref()
                .map(|m| frame.instruction.saturating_sub(m.base_address()));
            let function_offset = frame
                .function_base
                .filter(|b| *b <= frame.instruction)
                .map(|b| frame.instruction - b);
            frames.push(FrameReport {
                index: display_index,
                instruction: format!("{:#x}", frame.instruction),
                offset: offset.map(|o| format!("{:#x}", o)),
                module_index: module_idx,
                trust: frame.trust.as_str().to_string(),
                is_candidate: matches!(frame.trust, FrameTrust::Scan),
                function: frame.function_name.clone(),
                function_offset: function_offset.map(|o| format!("{:#x}", o)),
                file: frame.source_file_name.clone(),
                line: frame.source_line,
                inlines: frame
                    .inlines
                    .iter()
                    .map(|i| InlineFrameReport {
                        function: Some(i.function_name.clone()),
                        file: i.source_file_name.clone(),
                        line: i.source_line,
                        source_anchor: None,
                    })
                    .collect(),
                source_anchor: None,
            });
            display_index += 1;
        }
        // 崩溃线程顶部帧的寄存器。
        if Some(ti) == state.requesting_thread
            && let Some(frame) = stack.frames.first()
        {
            crashing_registers = Some(json_registers(&frame.context));
        }
        threads.push(ThreadReport {
            thread_id: stack.thread_id,
            name: stack.thread_name.clone(),
            info: call_stack_info_text(&stack.info),
            frames,
            registers: None,
        });
    }
    if let (Some(idx), Some(regs)) = (crashing_report_index, crashing_registers) {
        threads[idx].registers = Some(regs);
    }

    let sys = &state.system_info;
    Report {
        schema_version: REPORT_SCHEMA_VERSION,
        tool_name: TOOL_NAME.to_string(),
        tool_version: TOOL_VERSION.to_string(),
        dump_path: dump_path.display().to_string(),
        crash_time: state
            .time
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs()),
        process_id: state.process_id,
        exception,
        crashing_thread: crashing_report_index,
        system: SystemReport {
            os: format!("{}", sys.os),
            cpu: format!("{}", sys.cpu),
            cpu_info: sys.cpu_info.clone(),
            os_version: sys.os_version.clone(),
        },
        threads,
        modules,
        sources: Vec::new(),
        source_mode: SourceMode::None,
        source_omitted_count: 0,
        source_max_bytes: 0,
    }
}

fn call_stack_info_text(info: &CallStackInfo) -> Option<String> {
    match info {
        CallStackInfo::Ok => None,
        CallStackInfo::MissingContext => Some("缺少寄存器上下文,无法展开".into()),
        CallStackInfo::MissingMemory => Some("缺少栈内存,展开中断".into()),
        CallStackInfo::UnsupportedCpu => Some("不支持的 CPU 架构".into()),
        CallStackInfo::DumpThreadSkipped => Some("写 dump 的线程,已跳过".into()),
    }
}

/// 与 minidump-stackwalk 相同的方式导出通用寄存器。
fn json_registers(ctx: &minidump::MinidumpContext) -> std::collections::BTreeMap<String, String> {
    use std::collections::HashSet;
    let valid: HashSet<&str> = match &ctx.valid {
        minidump::MinidumpContextValidity::All => {
            ctx.general_purpose_registers().iter().copied().collect()
        }
        minidump::MinidumpContextValidity::Some(which) => which.iter().copied().collect(),
    };
    let mut out = std::collections::BTreeMap::new();
    for reg in ctx.general_purpose_registers() {
        if valid.contains(reg) {
            out.insert(reg.to_string(), ctx.format_register(reg));
        }
    }
    out
}

/// 收集源码引用(崩溃线程优先)。以 (路径, Build ID) 为键:同一源码
/// 路径可能由不同构建的模块引用,各构建的文件内容可能不同,必须分开。
fn collect_source_references(report: &mut Report) -> Vec<(String, Option<String>, Vec<u32>)> {
    let mut ordered: Vec<(String, Option<String>, Vec<u32>)> = Vec::new();
    let mut push_ref = |path: &str, line: u32, build_id: Option<String>| {
        if let Some(entry) = ordered
            .iter_mut()
            .find(|(p, b, _)| p == path && *b == build_id)
        {
            entry.2.push(line);
        } else {
            ordered.push((path.to_string(), build_id, vec![line]));
        }
    };

    // 崩溃线程在前。
    let mut indices: Vec<usize> = (0..report.threads.len()).collect();
    if let Some(c) = report.crashing_thread
        && let Some(pos) = indices.iter().position(|i| *i == c)
    {
        indices.remove(pos);
        indices.insert(0, c);
    }
    for ti in indices {
        let thread = &report.threads[ti];
        for frame in &thread.frames {
            if let (Some(file), Some(line)) = (&frame.file, frame.line) {
                let build_id = frame
                    .module_index
                    .and_then(|mi| report.modules.get(mi))
                    .and_then(|m| m.build_id.clone());
                push_ref(file, line, build_id);
            }
            for inline in &frame.inlines {
                if let (Some(file), Some(line)) = (&inline.file, inline.line) {
                    let build_id = frame
                        .module_index
                        .and_then(|mi| report.modules.get(mi))
                        .and_then(|m| m.build_id.clone());
                    push_ref(file, line, build_id);
                }
            }
        }
    }
    ordered
}

/// 帧所属模块的 Build ID。
fn module_build_id(modules: &[ModuleReport], index: Option<usize>) -> Option<&str> {
    index
        .and_then(|mi| modules.get(mi))
        .and_then(|m| m.build_id.as_deref())
}

/// 嵌入源码后回填帧到源码行的锚点。与收集端一致,以 (路径, 模块
/// Build ID) 为键查找源码条目,不同构建的同名文件各自跳转。
fn backfill_anchors(report: &mut Report) {
    let key_to_index: HashMap<(&str, Option<&str>), usize> = report
        .sources
        .iter()
        .map(|s| ((s.path.as_str(), s.build_id.as_deref()), s.index))
        .collect();
    for thread in &mut report.threads {
        for frame in &mut thread.frames {
            let build_id = module_build_id(&report.modules, frame.module_index);
            if let Some(file) = &frame.file
                && let Some(line) = frame.line
                && let Some(&si) = key_to_index.get(&(file.as_str(), build_id))
            {
                let src = &report.sources[si];
                if matches!(src.status, SourceStatus::Embedded { .. }) {
                    frame.source_anchor = Some(SourceAnchor {
                        source_index: si,
                        line,
                    });
                }
            }
            for inline in &mut frame.inlines {
                if let (Some(file), Some(line)) = (&inline.file, inline.line)
                    && let Some(&si) = key_to_index.get(&(file.as_str(), build_id))
                {
                    let src = &report.sources[si];
                    if matches!(src.status, SourceStatus::Embedded { .. }) {
                        inline.source_anchor = Some(SourceAnchor {
                            source_index: si,
                            line,
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P2-7:同一路径由两个构建引用时,各模块的栈帧应回填到各自构建的
    /// 源码条目锚点,而不是合并到同一份源码。
    #[test]
    fn backfill_anchors_keyed_by_build_id_and_path() {
        let frame = |module_index: Option<usize>, line: u32| FrameReport {
            index: 0,
            instruction: "0x1000".into(),
            offset: None,
            module_index,
            trust: "cfi".into(),
            is_candidate: false,
            function: None,
            function_offset: None,
            file: Some("/src/shared/version.c".into()),
            line: Some(line),
            inlines: vec![],
            source_anchor: None,
        };
        let module = |index: usize, build_id: &str| ModuleReport {
            index,
            name: format!("m{index}"),
            code_file: format!("/lib/m{index}.so"),
            debug_file: None,
            base_address: "0x0".into(),
            size: 1,
            debug_id: None,
            build_id: Some(build_id.to_string()),
            code_id: None,
            version: None,
            executable: ArtifactStatus::NoSource,
            debuginfo: ArtifactStatus::NoSource,
            symbols: SymbolStatus::Missing {
                reason: String::new(),
            },
        };
        let source = |index: usize, build_id: &str| SourceFileReport {
            index,
            path: "/src/shared/version.c".into(),
            build_id: Some(build_id.to_string()),
            status: SourceStatus::Embedded { bytes: 10 },
            lines: Some(vec!["int version(void) { return 1; }".into()]),
            line_ranges: Some(vec![(1, 1)]),
        };

        let mut report = Report {
            schema_version: REPORT_SCHEMA_VERSION,
            tool_name: TOOL_NAME.to_string(),
            tool_version: TOOL_VERSION.to_string(),
            dump_path: "x.dmp".into(),
            crash_time: None,
            process_id: None,
            exception: None,
            crashing_thread: Some(0),
            system: SystemReport {
                os: "Linux".into(),
                cpu: "x86_64".into(),
                cpu_info: None,
                os_version: None,
            },
            threads: vec![ThreadReport {
                thread_id: 1,
                name: None,
                info: None,
                frames: vec![frame(Some(0), 1), frame(Some(1), 1)],
                registers: None,
            }],
            modules: vec![module(0, "aa112233"), module(1, "bb445566")],
            sources: vec![source(0, "aa112233"), source(1, "bb445566")],
            source_mode: SourceMode::Context,
            source_omitted_count: 0,
            source_max_bytes: 1024,
        };

        backfill_anchors(&mut report);
        let frames = &report.threads[0].frames;
        let a = frames[0].source_anchor.as_ref().expect("构建 A 应有锚点");
        let b = frames[1].source_anchor.as_ref().expect("构建 B 应有锚点");
        assert_eq!(a.source_index, 0, "构建 A 的帧跳到版本 A 的源码");
        assert_eq!(b.source_index, 1, "构建 B 的帧跳到版本 B 的源码");
    }
}
