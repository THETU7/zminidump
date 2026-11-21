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

        /// 允许读取源码的本地根目录,可重复;默认不读取本机源码文件
        #[arg(long = "source-root")]
        source_roots: Vec<PathBuf>,

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
            source_roots,
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
                source_roots,
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

/// 规范化路径用于比较:优先 canonicalize(解析符号链接与 `..`);
/// 文件不存在(通常是待写入的输出)时规范化已存在的父目录再拼接文件名。
fn resolve_for_compare(p: &std::path::Path) -> Option<std::path::PathBuf> {
    if let Ok(c) = p.canonicalize() {
        return Some(c);
    }
    let parent = p.parent()?;
    let leaf = p.file_name()?;
    let parent = parent.canonicalize().ok()?;
    Some(parent.join(leaf))
}

/// 绝对化并词法归一(`.` / `..`)后的路径;两侧都无法访问文件系统时的
/// 最终比较依据。
fn lexical_absolute(p: &std::path::Path) -> std::path::PathBuf {
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let mut out = std::path::PathBuf::new();
    for comp in abs.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// 已存在文件的唯一身份:Unix 上为设备号 + inode(同一文件的不同
/// 硬链接名在此相等,canonicalize 无法识别)。
#[cfg(unix)]
fn same_existing_files(a: &std::path::Path, b: &std::path::Path) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    let x = std::fs::metadata(a).ok()?;
    let y = std::fs::metadata(b).ok()?;
    Some((x.dev(), x.ino()) == (y.dev(), y.ino()))
}

/// Windows 上的同文件判定:以独占共享模式依次打开两个文件。NTFS 上
/// 同一文件的第二次独占打开会因共享冲突失败(不同硬链接名也一样);
/// 其他进程占用导致的失败也会被保守地视为同一文件(宁可拒绝写入)。
#[cfg(windows)]
fn same_existing_files(a: &std::path::Path, b: &std::path::Path) -> Option<bool> {
    use std::os::windows::fs::OpenOptionsExt;
    let open_exclusive = |p: &std::path::Path| {
        std::fs::OpenOptions::new()
            .access_mode(0) // 仅查询属性
            .share_mode(0) // 独占
            .open(p)
    };
    let _ha = open_exclusive(a).ok()?;
    match open_exclusive(b) {
        Ok(_hb) => Some(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
        Err(_) => Some(true),
    }
}

/// 判断两个路径是否指向同一文件;覆盖相对路径、`..`、符号链接与硬链接
/// 别名等情形,防止报告输出覆盖输入 dump 或先前的报告。
fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    // 双方都已存在:比较文件身份(硬链接也视为同一文件)。
    if a.is_file()
        && b.is_file()
        && let Some(same) = same_existing_files(a, b)
    {
        return same;
    }
    match (resolve_for_compare(a), resolve_for_compare(b)) {
        (Some(x), Some(y)) => x == y,
        _ => lexical_absolute(a) == lexical_absolute(b),
    }
}

/// 拒绝会覆盖输入 dump 或互相覆盖的输出组合。
fn check_output_conflicts(
    dump: &std::path::Path,
    html: Option<&std::path::Path>,
    json: Option<&std::path::Path>,
) -> Result<(), String> {
    for (label, out) in [("HTML", html), ("JSON", json)] {
        if let Some(out) = out
            && same_file(out, dump)
        {
            return Err(format!(
                "{label} 输出 {} 与输入 dump 指向同一文件,拒绝覆盖",
                out.display()
            ));
        }
    }
    if let (Some(h), Some(j)) = (html, json)
        && same_file(h, j)
    {
        return Err(format!(
            "HTML 输出 {} 与 JSON 输出 {} 指向同一文件,拒绝互相覆盖",
            h.display(),
            j.display()
        ));
    }
    Ok(())
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
    check_output_conflicts(dump, html, json)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn same_file_detects_aliases_and_lexical_duplicates() {
        let dir = std::env::temp_dir().join(format!("zmsame-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dump = dir.join("crash.dmp");
        std::fs::write(&dump, b"dmp").unwrap();

        // 同一路径与相对 `..` 别名。
        assert!(same_file(&dump, &dump));
        assert!(same_file(
            &PathBuf::from(format!("{}/sub/../crash.dmp", dir.display())),
            &dump
        ));

        // 不同文件不算同一目标。
        let other = dir.join("other.dmp");
        std::fs::write(&other, b"x").unwrap();
        assert!(!same_file(&other, &dump));

        // 符号链接别名与硬链接别名(不同路径名指向同一文件)。
        #[cfg(unix)]
        {
            let alias = dir.join("alias.dmp");
            std::os::unix::fs::symlink(&dump, &alias).unwrap();
            assert!(same_file(&alias, &dump));

            let hardlink = dir.join("hard.dmp");
            std::fs::hard_link(&dump, &hardlink).unwrap();
            assert!(
                same_file(&hardlink, &dump),
                "硬链接指向同一 inode,必须视为同一文件"
            );
        }

        // 输出文件尚不存在:退化为词法比较,`..` 与相对路径仍可识别。
        assert!(same_file(Path::new("a/../b.html"), Path::new("b.html")));
        assert!(!same_file(Path::new("b.html"), Path::new("c.html")));

        std::fs::remove_dir_all(&dir).ok();
    }
}
