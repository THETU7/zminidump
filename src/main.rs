//! Zminidump CLI。

use std::{path::PathBuf, process::ExitCode, time::Duration};

use clap::{Parser, Subcommand, ValueEnum};
use zminidump::{AnalyzeOptions, analyze_dump, render_json, report::SourceMode};

#[derive(Parser)]
#[command(
    name = "zminidump",
    version,
    about = "本地原生崩溃分析工具:分析 Breakpad/Crashpad minidump,导出离线 HTML / JSON 报告",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 分析一个 minidump 并导出报告
    Analyze {
        /// 输入的 .dmp 文件
        dump: PathBuf,

        /// 输出单文件 HTML 报告路径
        #[arg(long)]
        html: Option<PathBuf>,

        /// 输出 JSON 报告路径
        #[arg(long)]
        json: Option<PathBuf>,

        /// 源码嵌入模式:none 仅路径行号,context 关键帧附近片段(默认),full 完整文件
        #[arg(long = "include-source", value_enum, default_value = "context")]
        include_source: IncludeSource,

        /// context 模式下关键帧前后各嵌入的行数
        #[arg(long, default_value_t = 3)]
        context_lines: u32,

        /// 符号产物目录(ELF / 独立 .debug / 预生成 .sym),可重复
        #[arg(long = "symbol-path")]
        symbol_paths: Vec<PathBuf>,

        /// 主程序路径(辅助匹配;仍按 Build ID 核验)
        #[arg(long)]
        binary: Option<PathBuf>,

        /// 独立调试文件路径
        #[arg(long = "debug-file")]
        debug_file: Option<PathBuf>,

        /// 额外 debuginfod 服务器,可重复;默认读取 DEBUGINFOD_URLS
        #[arg(long = "debuginfod")]
        debuginfod: Vec<String>,

        /// 禁用所有 debuginfod 查询(离线分析)
        #[arg(long)]
        no_debuginfod: bool,

        /// 缓存目录;默认 $XDG_CACHE_HOME/zminidump
        #[arg(long)]
        cache: Option<PathBuf>,

        /// 嵌入源码总大小上限(字节)
        #[arg(long, default_value_t = 2 * 1024 * 1024)]
        max_source_bytes: u64,

        /// 单次网络请求超时(秒)
        #[arg(long, default_value_t = 60)]
        timeout: u64,

        /// 单次下载大小上限(字节)
        #[arg(long, default_value_t = 512 * 1024 * 1024)]
        max_download_bytes: u64,

        /// 最大并发下载数
        #[arg(long, default_value_t = 4)]
        jobs: usize,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum IncludeSource {
    None,
    Context,
    Full,
}

impl From<IncludeSource> for SourceMode {
    fn from(v: IncludeSource) -> Self {
        match v {
            IncludeSource::None => SourceMode::None,
            IncludeSource::Context => SourceMode::Context,
            IncludeSource::Full => SourceMode::Full,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Analyze {
            dump,
            html,
            json,
            include_source,
            context_lines,
            symbol_paths,
            binary,
            debug_file,
            debuginfod,
            no_debuginfod,
            cache,
            max_source_bytes,
            timeout,
            max_download_bytes,
            jobs,
        } => {
            let debuginfod_urls = if no_debuginfod {
                Vec::new()
            } else {
                let mut urls = debuginfod;
                if urls.is_empty() {
                    urls = zminidump::analyze::debuginfod_urls_from_env();
                }
                urls
            };

            let opts = AnalyzeOptions {
                symbol_paths,
                user_binary: binary,
                user_debug_file: debug_file,
                debuginfod_urls,
                cache_dir: cache.unwrap_or_else(zminidump::analyze::default_cache_dir),
                source_mode: include_source.into(),
                context_lines,
                max_source_bytes,
                limits: zminidump::artifacts::Limits {
                    timeout: Duration::from_secs(timeout),
                    max_download_bytes,
                    max_concurrent: jobs,
                },
            };

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("无法创建异步运行时");

            match rt.block_on(run_analyze(&dump, &opts, html.as_deref(), json.as_deref())) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("zminidump: 分析失败:{e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

async fn run_analyze(
    dump: &std::path::Path,
    opts: &AnalyzeOptions,
    html: Option<&std::path::Path>,
    json: Option<&std::path::Path>,
) -> Result<(), String> {
    if html.is_none() && json.is_none() {
        return Err("请至少指定 --html 或 --json 之一".into());
    }
    let report = analyze_dump(dump, opts).await.map_err(|e| e.to_string())?;

    if let Some(path) = json {
        let text = render_json(&report).map_err(|e| format!("JSON 序列化失败:{e}"))?;
        std::fs::write(path, text).map_err(|e| format!("写入 {} 失败:{e}", path.display()))?;
        eprintln!("已写入 JSON 报告:{}", path.display());
    }
    if let Some(path) = html {
        let text = zminidump::html::render_html(&report);
        std::fs::write(path, text).map_err(|e| format!("写入 {} 失败:{e}", path.display()))?;
        eprintln!("已写入 HTML 报告:{}", path.display());
    }

    // 摘要输出。
    if let Some(exception) = &report.exception {
        let thread = report.crashing_thread.and_then(|i| report.threads.get(i));
        eprintln!(
            "崩溃:{},地址 {},线程 {}",
            exception.reason,
            exception.address,
            thread.map(|t| t.thread_id).unwrap_or(0)
        );
        if let Some(t) = thread {
            for frame in t.frames.iter().take(8) {
                eprintln!(
                    "  #{:<2} {} {} {}",
                    frame.index,
                    frame.instruction,
                    frame.function.as_deref().unwrap_or("??"),
                    frame
                        .file
                        .as_deref()
                        .map(|f| format!(
                            "{f}:{}",
                            frame.line.map(|l| l.to_string()).unwrap_or_default()
                        ))
                        .unwrap_or_default()
                );
            }
        }
    }
    Ok(())
}
