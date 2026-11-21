//! 端到端测试(Linux x86-64):真实崩溃 → 真实 minidump → 分析与导出。
//!
//! 样本满足设计验收要求:剥离的 PIE 主程序 + 独立 `.debug` + 自有
//! `.so`(同样剥离并保留独立调试文件),CFI 依赖 `.eh_frame`
//! (`-fomit-frame-pointer`)。若无 gcc/objcopy 工具链则跳过。

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::{
    fs,
    io::{Read as _, Write as _},
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};

use zminidump::report::{ArtifactOrigin, ArtifactStatus, SourceMode, SourceStatus, SymbolStatus};
use zminidump::{AnalyzeOptions, Report, analyze_dump};

// ---------------------------------------------------------------------------
// 固件:编译崩溃样本
// ---------------------------------------------------------------------------

const LIBCRASH_C: &str = r#"/* 客户共享库样本 */
#define _GNU_SOURCE
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "libcrash.h"

static const char *ctx_path;

/* 崩溃时保存故障上下文并 SIGSTOP,等待外部写入 minidump。 */
static void save_context(int sig, siginfo_t *si, void *uctx) {
    (void)sig;
    ucontext_t *uc = (ucontext_t *)uctx;
    int fd = open(ctx_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd >= 0) {
        ssize_t (*w)(int, const void *, size_t) = write;
        (void)!w(fd, uc, sizeof(*uc));
        (void)!w(fd, si, sizeof(*si));
        close(fd);
    }
    raise(SIGSTOP);
    for (;;) pause();
}

__attribute__((noinline)) static int inner(int *p) {
    return *p; /* CRASH_POINT */
}

__attribute__((noinline)) int libcrash_entry(int v) {
    int *bad = (int *)(long)v;
    return inner(bad);
}

int crasher_main(const char *path) {
    ctx_path = path;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = save_context;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    return libcrash_entry(0);
}
"#;

const LIBCRASH_H: &str = "int crasher_main(const char *path);\n";

const MAIN_C: &str = r#"#include "libcrash.h"

int main(int argc, char **argv) {
    return crasher_main(argc > 1 ? argv[1] : "/tmp/zminidump-ctx");
}
"#;

fn have_tools() -> bool {
    ["gcc", "objcopy", "strip"]
        .iter()
        .all(|t| Command::new(t).arg("--version").output().is_ok())
}

/// 固件目录。名字带 HTML 特殊字符,用于验证报告转义。
fn fixture_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("e2e-{tag}-<崩溃&样本>-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// 编译并剥离样本;返回 (目录, libcrash.c 中 CRASH_POINT 行号, 变体标记)。
fn build_fixture(dir: &Path, variant: Option<&str>) -> (u32, u32) {
    let (lib_c, lib_h, main_c) = match variant {
        Some(v) => (
            LIBCRASH_C.replace("crasher_main", &format!("crasher_main_{v}")),
            LIBCRASH_H.replace("crasher_main", &format!("crasher_main_{v}")),
            MAIN_C.replace("crasher_main", &format!("crasher_main_{v}")),
        ),
        None => (
            LIBCRASH_C.to_string(),
            LIBCRASH_H.to_string(),
            MAIN_C.to_string(),
        ),
    };
    fs::write(dir.join("libcrash.c"), &lib_c).unwrap();
    fs::write(dir.join("libcrash.h"), &lib_h).unwrap();
    fs::write(dir.join("main.c"), &main_c).unwrap();

    let common = ["-O1", "-g", "-fomit-frame-pointer", "-fno-inline"];
    let run = |program: &str, args: &[&str]| {
        let out = Command::new(program)
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{program} {args:?} 失败:{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };

    run(
        "gcc",
        &[
            &["-c", "-fPIC", "libcrash.c", "-o", "libcrash.o"][..],
            &common,
        ]
        .concat(),
    );
    run(
        "gcc",
        &[
            &[
                "-shared",
                "libcrash.o",
                "-o",
                "libcrash.so",
                "-Wl,--build-id=sha1",
            ][..],
            &common[..0],
        ]
        .concat(),
    );
    run(
        "gcc",
        &[&["-c", "-fPIE", "main.c", "-o", "main.o"][..], &common].concat(),
    );
    run(
        "gcc",
        &[
            &[
                "main.o",
                "-L.",
                "-lcrash",
                "-Wl,-rpath,$ORIGIN",
                "-o",
                "crasher",
                "-pie",
                "-Wl,--build-id=sha1",
            ][..],
            &[],
        ]
        .concat(),
    );

    // 剥离 + 独立调试文件。
    run(
        "objcopy",
        &["--only-keep-debug", "libcrash.so", "libcrash.so.debug"],
    );
    run("strip", &["--strip-all", "libcrash.so"]);
    run(
        "objcopy",
        &["--only-keep-debug", "crasher", "crasher.debug"],
    );
    run("strip", &["--strip-all", "crasher"]);

    let crash_line = lib_c
        .lines()
        .position(|l| l.contains("CRASH_POINT"))
        .expect("CRASH_POINT 存在") as u32
        + 1;
    let entry_line = lib_c
        .lines()
        .position(|l| l.contains("crasher_main") && l.contains("return"))
        .map(|p| p as u32 + 1)
        .unwrap_or(0);
    let entry_line = if entry_line > 0 {
        entry_line
    } else {
        lib_c
            .lines()
            .position(|l| l.contains("libcrash_entry(0)"))
            .expect("entry 调用存在") as u32
            + 1
    };
    (crash_line, entry_line)
}

// ---------------------------------------------------------------------------
// 真实 minidump:fork + ptrace + minidump-writer
// ---------------------------------------------------------------------------

/// 让 crasher 崩溃,由父进程用 minidump-writer 写出真实 dump。
///
/// crasher 在 SIGSEGV 处理器中把故障上下文(ucontext + siginfo)写入
/// 文件并 SIGSTOP 自身;父进程随后成为唯一的 ptrace tracer,完成线程
/// 枚举、栈内存采集与异常流写入。
fn produce_minidump(crasher: &Path, dump_path: &Path) {
    let ctx_path = crasher.parent().unwrap().join("fault.ctx");
    let _ = std::fs::remove_file(&ctx_path);

    let mut child = Command::new(crasher)
        .arg(&ctx_path)
        .spawn()
        .expect("启动 crasher");
    let pid = child.id() as i32;

    // 等待 SIGSTOP(崩溃处理器触发)。
    unsafe {
        let mut status: i32 = 0;
        libc::waitpid(pid, &mut status, libc::WUNTRACED);
        assert!(
            libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP,
            "crasher 应停在 SIGSTOP,status={status}"
        );

        // 读取故障上下文。
        let bytes = fs::read(&ctx_path).expect("应有故障上下文文件");
        assert_eq!(
            bytes.len(),
            std::mem::size_of::<libc::ucontext_t>() + std::mem::size_of::<libc::siginfo_t>(),
            "上下文文件大小不匹配"
        );
        let uc: libc::ucontext_t = std::ptr::read(bytes.as_ptr() as *const libc::ucontext_t);
        let si: libc::siginfo_t =
            std::ptr::read(bytes.as_ptr().add(std::mem::size_of::<libc::ucontext_t>())
                as *const libc::siginfo_t);

        let mut ctx: crash_context::CrashContext = std::mem::zeroed();
        ctx.pid = pid;
        ctx.tid = pid;
        ctx.context.uc_mcontext.gregs = uc.uc_mcontext.gregs;
        ctx.siginfo.ssi_signo = libc::SIGSEGV as u32;
        ctx.siginfo.ssi_errno = si.si_errno as i32;
        ctx.siginfo.ssi_code = si.si_code as i32;
        ctx.siginfo.ssi_addr = si.si_addr() as usize as u64;

        let mut config = minidump_writer::minidump_writer::MinidumpWriterConfig::new(pid, pid);
        config.set_crash_context(minidump_writer::CrashContextExt { inner: ctx });
        let mut file = fs::File::create(dump_path).unwrap();
        config.write(&mut file).expect("写出 minidump");

        // 清理子进程。
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, &mut status, 0);
    }
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

fn base_options(symbol_paths: Vec<PathBuf>, cache: &Path) -> AnalyzeOptions {
    AnalyzeOptions {
        symbol_paths,
        debuginfod_urls: Vec::new(),
        cache_dir: cache.to_path_buf(),
        source_mode: SourceMode::Context,
        context_lines: 2,
        max_source_bytes: 256 * 1024,
        ..Default::default()
    }
}

fn run_analyze(dump: &Path, opts: &AnalyzeOptions) -> Report {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(analyze_dump(dump, opts)).expect("分析成功")
}

#[test]
fn real_crash_unwinds_to_source_lines_with_cfi() {
    if !have_tools() {
        eprintln!("缺少 gcc/objcopy/strip,跳过端到端测试");
        return;
    }
    let dir = fixture_dir("main");
    let (crash_line, level1_line) = build_fixture(&dir, None);
    let dump = dir.join("crash.dmp");
    produce_minidump(&dir.join("crasher"), &dump);
    assert!(dump.metadata().unwrap().len() > 0);

    let report = run_analyze(&dump, &{
        let mut opts = base_options(vec![dir.clone()], &dir.join("cache"));
        // P1-4:本地源码嵌入需要显式授权固件目录为源码根目录。
        opts.source_roots = vec![dir.clone()];
        opts
    });

    // 异常与崩溃线程。
    let exception = report.exception.as_ref().expect("应有异常记录");
    assert_eq!(exception.address, "0x0");
    let crash_idx = report.crashing_thread.expect("应有崩溃线程");
    let thread = &report.threads[crash_idx];
    assert!(!thread.frames.is_empty());
    assert!(thread.registers.is_some(), "崩溃线程应有寄存器");

    // 模块状态:自有 .so 与主程序均应匹配产物并加载符号。
    let lib = report
        .modules
        .iter()
        .find(|m| m.name == "libcrash.so")
        .expect("模块列表含 libcrash.so");
    assert!(
        matches!(lib.executable, ArtifactStatus::Ok { .. }),
        "exe 状态:{:?}",
        lib.executable
    );
    assert!(
        matches!(lib.debuginfo, ArtifactStatus::Ok { .. }),
        "debug 状态:{:?}",
        lib.debuginfo
    );
    match &lib.symbols {
        SymbolStatus::Loaded {
            has_cfi, has_lines, ..
        } => {
            assert!(has_cfi, "libcrash 符号应含 CFI(eh_frame)");
            assert!(has_lines, "libcrash 符号应含行号(.debug)");
        }
        other => panic!("libcrash 符号状态异常:{other:?}"),
    }
    let exe = report
        .modules
        .iter()
        .find(|m| m.name == "crasher")
        .expect("模块列表含 crasher");
    assert!(matches!(exe.executable, ArtifactStatus::Ok { .. }));
    assert!(
        matches!(exe.symbols, SymbolStatus::Loaded { .. }),
        "{:?}",
        exe.symbols
    );

    // 崩溃帧:libcrash.so 内 inner 的空指针解引用。
    let frame0 = &thread.frames[0];
    assert_eq!(frame0.trust, "context", "顶部帧应来自异常上下文");
    assert!(
        frame0.function.as_deref().unwrap_or("").contains("inner"),
        "{:?}",
        frame0.function
    );
    assert!(
        frame0.file.as_deref().unwrap_or("").ends_with("libcrash.c"),
        "{:?}",
        frame0.file
    );
    assert_eq!(
        frame0.line,
        Some(crash_line),
        "崩溃行号不匹配:{:?}",
        frame0.line
    );

    // 主程序链路帧:crasher_main(libcrash.c)与 main(main.c)。
    let entry_frame = thread
        .frames
        .iter()
        .find(|f| {
            f.function
                .as_deref()
                .map(|n| n.contains("crasher_main"))
                .unwrap_or(false)
        })
        .expect("应展开到 crasher_main 帧");
    assert!(
        entry_frame
            .file
            .as_deref()
            .unwrap_or("")
            .ends_with("libcrash.c")
    );
    assert_eq!(
        entry_frame.line,
        Some(level1_line),
        "crasher_main 行号不匹配"
    );

    let main_frame = thread
        .frames
        .iter()
        .find(|f| f.function.as_deref() == Some("main"))
        .expect("应展开到 main 帧");
    assert!(main_frame.file.as_deref().unwrap_or("").ends_with("main.c"));

    // 展开*CFI*规则(-fomit-frame-pointer 下帧指针链不可用)。
    assert!(
        thread.frames.iter().any(|f| f.trust == "cfi"),
        "应存在 CFI 展开的帧:{:?}",
        thread
            .frames
            .iter()
            .map(|f| f.trust.clone())
            .collect::<Vec<_>>()
    );

    // 源码嵌入:关键帧带锚点,源码段含崩溃行。
    assert!(frame0.source_anchor.is_some(), "崩溃帧应有源码锚点");
    let src = &report.sources[frame0.source_anchor.as_ref().unwrap().source_index];
    assert!(src.path.ends_with("libcrash.c"));
    let anchor_line = frame0.source_anchor.as_ref().unwrap().line as usize;
    let ranges = src.line_ranges.as_ref().unwrap();
    assert!(
        ranges
            .iter()
            .any(|(a, b)| anchor_line >= *a as usize && anchor_line <= *b as usize)
    );
    assert!(
        src.lines
            .as_ref()
            .unwrap()
            .iter()
            .any(|l| l.contains("CRASH_POINT"))
    );

    // JSON 可序列化、结构版本一致。
    let json = zminidump::render_json(&report).unwrap();
    assert!(json.contains("\"schema_version\": 1"));

    // HTML 转义:固件目录名含 <>&,不得出现未转义的路径。
    let html = zminidump::html::render_html(&report);
    assert!(!html.contains("e2e-main-<崩溃&样本>"), "HTML 必须转义路径");
    assert!(html.contains("e2e-main-&lt;崩溃&amp;样本&gt;"));
    assert!(html.contains("id=\"module-"));
    assert!(html.contains(&format!("id=\"src-{}-L{}\"", src.index, crash_line)));
}

#[test]
fn wrong_build_id_elf_is_rejected() {
    if !have_tools() {
        eprintln!("缺少 gcc/objcopy/strip,跳过错误版本拒绝测试");
        return;
    }
    let dir = fixture_dir("wrong");
    // 变体库的 Build ID 与真实固件不同。
    let wrong_dir = dir.join("wrong-elfs");
    fs::create_dir_all(&wrong_dir).unwrap();
    let _ = build_fixture(&wrong_dir, Some("v2"));
    // 真实固件在另一目录,但符号路径只给错误目录。
    let good_dir = dir.join("good");
    fs::create_dir_all(&good_dir).unwrap();
    build_fixture(&good_dir, None);
    let dump = good_dir.join("crash.dmp");
    produce_minidump(&good_dir.join("crasher"), &dump);

    let report = run_analyze(&dump, &base_options(vec![wrong_dir], &dir.join("cache")));

    let lib = report
        .modules
        .iter()
        .find(|m| m.name == "libcrash.so")
        .expect("应有 libcrash 模块");
    assert!(
        !matches!(lib.executable, ArtifactStatus::Ok { .. }),
        "错误 Build ID 的 ELF 必须被拒绝:{:?}",
        lib.executable
    );
    assert!(
        matches!(lib.executable, ArtifactStatus::IdentityMismatch { .. })
            || matches!(lib.debuginfo, ArtifactStatus::IdentityMismatch { .. }),
        "同名但 Build ID 不符的 ELF 应报告身份不匹配:{:?} / {:?}",
        lib.executable,
        lib.debuginfo
    );
    // 已知帧与诊断仍可查看。
    let thread = &report.threads[report.crashing_thread.unwrap()];
    let frame0 = &thread.frames[0];
    assert_eq!(frame0.trust, "context");
    assert!(frame0.function.is_none(), "无符号时函数未知");
    assert!(frame0.offset.is_some(), "模块内偏移仍应保留");
    assert!(matches!(lib.symbols, SymbolStatus::Missing { .. }));
}

// ---------------------------------------------------------------------------
// 本地 debuginfod 服务 + 缓存复用
// ---------------------------------------------------------------------------

/// 极简 HTTP 服务,模拟 debuginfod 的 buildid 端点。
struct FakeDebuginfod {
    hits: Arc<Mutex<std::collections::HashMap<String, usize>>>,
    url: String,
}

/// 服务端归档内容。
#[derive(Default)]
struct Served {
    /// kind(debuginfo/executable)→ build_id → 文件。
    files: std::collections::HashMap<String, std::collections::HashMap<String, PathBuf>>,
    /// build_id → 源码相对路径(去掉开头 `/`)→ 文件。
    sources: std::collections::HashMap<String, std::collections::HashMap<String, PathBuf>>,
    /// 对所有 `/source` 请求返回 503(模拟服务端故障)。
    sources_always_error: bool,
}

/// 请求路径里的百分号编码解码(服务端视角)。
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            )
        {
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl FakeDebuginfod {
    fn start(served: Arc<Served>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let hit_counter = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let files = served.clone();
                let hits = hit_counter.clone();
                std::thread::spawn(move || handle(stream, files, hits));
            }
        });
        Self {
            hits,
            url: format!("http://127.0.0.1:{port}"),
        }
    }

    fn count(&self, kind: &str) -> usize {
        *self.hits.lock().unwrap().get(kind).unwrap_or(&0)
    }
}

fn handle(
    mut stream: std::net::TcpStream,
    served: Arc<Served>,
    hits: Arc<Mutex<std::collections::HashMap<String, usize>>>,
) {
    let mut buf = [0u8; 4096];
    let Ok(n) = stream.read(&mut buf) else { return };
    let request = String::from_utf8_lossy(&buf[..n]);
    let Some(line) = request.lines().next() else {
        return;
    };
    let mut parts = line.split_whitespace();
    let _method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    // /buildid/{id}/{kind} 或 /buildid/{id}/source/{path...}
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    let hit: Option<Vec<u8>> = if segments.len() == 3 && segments[0] == "buildid" {
        let (id, kind) = (segments[1], segments[2]);
        served
            .files
            .get(kind)
            .and_then(|m| m.get(id))
            .and_then(|f| fs::read(f).ok())
    } else if segments.len() >= 4 && segments[0] == "buildid" && segments[2] == "source" {
        let id = segments[1];
        let decoded = percent_decode(&segments[3..].join("/"));
        served
            .sources
            .get(id)
            .and_then(|m| m.get(&decoded))
            .and_then(|f| fs::read(f).ok())
    } else {
        None
    };
    let counter_key = if segments.len() >= 4 && segments[2] == "source" {
        "source"
    } else if segments.len() == 3 {
        segments[2]
    } else {
        ""
    };
    if segments.len() >= 4
        && segments[0] == "buildid"
        && segments[2] == "source"
        && served.sources_always_error
    {
        stream
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
        return;
    }
    if let Some(bytes) = hit {
        *hits
            .lock()
            .unwrap()
            .entry(counter_key.to_string())
            .or_insert(0) += 1;
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bytes.len()
        );
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(&bytes).unwrap();
        return;
    }
    stream
        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .unwrap();
}

fn elf_build_id(path: &Path) -> String {
    let bytes = fs::read(path).unwrap();
    let meta = zminidump::artifacts::probe_elf_bytes(&bytes).expect("应能解析 ELF");
    meta.build_id.expect("固件应有 Build ID")
}

#[test]
fn debuginfod_download_and_cache_reuse() {
    if !have_tools() {
        eprintln!("缺少 gcc/objcopy/strip,跳过 debuginfod 测试");
        return;
    }
    let dir = fixture_dir("dinfod");
    build_fixture(&dir, None);
    let dump = dir.join("crash.dmp");
    produce_minidump(&dir.join("crasher"), &dump);

    // 服务端按 Build ID 归档:独立调试文件与剥离后的可执行文件。
    let mut served = Served::default();
    for (kind, suffix) in [("debuginfo", ".debug"), ("executable", "")] {
        let mut per_kind = std::collections::HashMap::new();
        for name in ["crasher", "libcrash.so"] {
            let path = dir.join(format!("{name}{suffix}"));
            per_kind.insert(elf_build_id(&path), path);
        }
        served.files.insert(kind.to_string(), per_kind);
    }
    let server = FakeDebuginfod::start(Arc::new(served));

    let cache = dir.join("cache");
    let opts = AnalyzeOptions {
        symbol_paths: vec![dir.join("empty")], // 不直接给固件目录,强制走网络
        debuginfod_urls: vec![server.url.clone()],
        cache_dir: cache.clone(),
        ..base_options(vec![], &cache)
    };
    // 符号路径里放一个空目录避免误扫固件。
    fs::create_dir_all(dir.join("empty")).unwrap();

    let report = run_analyze(&dump, &opts);
    let lib = report
        .modules
        .iter()
        .find(|m| m.name == "libcrash.so")
        .unwrap();
    assert!(
        matches!(lib.debuginfo, ArtifactStatus::Ok { .. }),
        "应从 debuginfod 获取调试文件:{:?}",
        lib.debuginfo
    );
    match &lib.symbols {
        SymbolStatus::Loaded {
            has_cfi, has_lines, ..
        } => {
            assert!(has_lines, "调试文件提供行号");
            assert!(has_cfi, "按需下载的可执行文件提供 CFI");
        }
        other => panic!("符号应加载:{other:?}"),
    }
    // 每个模块的每种产物只请求一次(合并并发)。
    assert_eq!(
        server.count("debuginfo"),
        2,
        "两个自有模块各请求一次调试文件"
    );
    assert!(
        server.count("executable") >= 1,
        "缺少 CFI 时应按需下载可执行文件"
    );

    // 第二次分析:命中缓存,不再发起请求。
    let report2 = run_analyze(&dump, &opts);
    let lib2 = report2
        .modules
        .iter()
        .find(|m| m.name == "libcrash.so")
        .unwrap();
    assert!(matches!(lib2.debuginfo, ArtifactStatus::Ok { .. }));
    assert!(matches!(lib2.symbols, SymbolStatus::Loaded { .. }));
    assert_eq!(server.count("debuginfo"), 2, "第二次分析应命中缓存");
    assert!(cache.join("debuginfod").exists(), "下载应写入缓存目录");
}

// ---------------------------------------------------------------------------
// 预生成 .sym 与混合来源(P1 回归)
// ---------------------------------------------------------------------------

/// 用 dump_syms 生成标准 Breakpad `.sym`(独立调试文件 + 剥离镜像合并)。
fn generate_standard_sym(dir: &Path) -> Vec<u8> {
    use dump_syms::{object_info::ObjectInfo, platform::Platform};
    let debug = fs::read(dir.join("libcrash.so.debug")).unwrap();
    let exe = fs::read(dir.join("libcrash.so")).unwrap();
    let d = ObjectInfo::from_elf(&debug, "libcrash.so", Platform::Linux, None, true).unwrap();
    let e = ObjectInfo::from_elf(&exe, "libcrash.so", Platform::Linux, None, true).unwrap();
    let merged = ObjectInfo::merge(d, e).unwrap();
    let mut text = Vec::new();
    merged.dump(&mut text).unwrap();
    text
}

/// P1-1:标准 Breakpad `.sym`(MODULE 行使用 Breakpad 格式标识)应能命中,
/// 并用该文件提供的 CFI 展开到预期调用帧;仅提供 .sym 与 dump 即可。
#[test]
fn pregenerated_sym_unwinds_with_cfi() {
    if !have_tools() {
        eprintln!("缺少 gcc/objcopy/strip,跳过 .sym 测试");
        return;
    }
    let dir = fixture_dir("sym");
    build_fixture(&dir, None);
    let dump = dir.join("crash.dmp");
    produce_minidump(&dir.join("crasher"), &dump);

    let text = generate_standard_sym(&dir);
    let first_line = String::from_utf8_lossy(&text)
        .lines()
        .next()
        .unwrap()
        .to_string();
    assert!(
        first_line.starts_with("MODULE "),
        "标准 .sym 应有 MODULE 行:{first_line}"
    );
    let sym_dir = dir.join("syms");
    fs::create_dir_all(&sym_dir).unwrap();
    fs::write(sym_dir.join("libcrash.so.sym"), &text).unwrap();

    // 符号目录只提供 .sym(不含 ELF)。
    let report = run_analyze(&dump, &base_options(vec![sym_dir], &dir.join("cache")));

    let lib = report
        .modules
        .iter()
        .find(|m| m.name == "libcrash.so")
        .expect("应有 libcrash.so 模块");
    match &lib.symbols {
        SymbolStatus::Loaded {
            detail,
            has_cfi,
            has_lines,
            ..
        } => {
            assert!(detail.contains("预生成"), "应命中预生成 .sym:{detail}");
            assert!(has_cfi, ".sym 应含 CFI 展开规则");
            assert!(has_lines, ".sym 应含行号");
        }
        other => panic!("libcrash 符号状态异常:{other:?}"),
    }
    let thread = &report.threads[report.crashing_thread.unwrap()];
    assert!(
        thread.frames[0]
            .function
            .as_deref()
            .unwrap_or("")
            .contains("inner"),
        "{:?}",
        thread.frames[0].function
    );
    assert!(
        thread.frames.iter().any(|f| f.trust == "cfi"),
        "应使用 .sym 提供的 CFI 展开"
    );
}

/// P1-2:用户指定的主程序与 `.so` 身份不匹配时,只拒绝该候选;
/// `.so` 仍应从 debuginfod 拉取正确版本(符号目录中的同名错误版本同理)。
#[test]
fn user_binary_mismatch_falls_back_to_remote() {
    if !have_tools() {
        eprintln!("缺少 gcc/objcopy/strip,跳过混合来源测试");
        return;
    }
    let dir = fixture_dir("mixed");
    let good_dir = dir.join("good");
    fs::create_dir_all(&good_dir).unwrap();
    build_fixture(&good_dir, None);
    let dump = good_dir.join("crash.dmp");
    produce_minidump(&good_dir.join("crasher"), &dump);

    // 符号目录中放入同名错误版本(v2 变体,Build ID 不同)。
    let wrong_dir = dir.join("wrong-elfs");
    fs::create_dir_all(&wrong_dir).unwrap();
    build_fixture(&wrong_dir, Some("v2"));

    // 服务端只归档正确的 .so:调试文件与可执行镜像。
    let mut served = Served::default();
    for (kind, suffix) in [("debuginfo", ".debug"), ("executable", "")] {
        served.files.insert(
            kind.to_string(),
            std::collections::HashMap::from([(
                elf_build_id(&good_dir.join(format!("libcrash.so{suffix}"))),
                good_dir.join(format!("libcrash.so{suffix}")),
            )]),
        );
    }
    let server = FakeDebuginfod::start(Arc::new(served));

    let cache = dir.join("cache");
    let opts = AnalyzeOptions {
        symbol_paths: vec![wrong_dir],
        user_binary: Some(good_dir.join("crasher")),
        debuginfod_urls: vec![server.url.clone()],
        cache_dir: cache.clone(),
        ..base_options(vec![], &cache)
    };
    let report = run_analyze(&dump, &opts);

    // 主程序使用用户显式指定的本地产物。
    let exe = report
        .modules
        .iter()
        .find(|m| m.name == "crasher")
        .expect("应有 crasher 模块");
    match &exe.executable {
        ArtifactStatus::Ok { origin, .. } => assert!(
            matches!(origin, ArtifactOrigin::UserSpecified { .. }),
            "主程序应用 --binary:{origin:?}"
        ),
        other => panic!("主程序应匹配 --binary:{other:?}"),
    }

    // 动态库不受用户主程序/同名错误版本影响,从服务端拉取正确版本。
    let lib = report
        .modules
        .iter()
        .find(|m| m.name == "libcrash.so")
        .expect("应有 libcrash.so 模块");
    match &lib.debuginfo {
        ArtifactStatus::Ok { origin, .. } => assert!(
            matches!(origin, ArtifactOrigin::Debuginfod { .. }),
            ".so 调试文件应来自服务端:{origin:?}"
        ),
        other => panic!(".so 调试文件应来自服务端:{other:?}"),
    }
    match &lib.symbols {
        SymbolStatus::Loaded {
            has_cfi, has_lines, ..
        } => {
            assert!(has_cfi, "远程镜像应补齐 CFI");
            assert!(has_lines, "调试文件应提供行号");
        }
        other => panic!("libcrash 符号应加载:{other:?}"),
    }
    let thread = &report.threads[report.crashing_thread.unwrap()];
    assert!(
        thread.frames[0]
            .function
            .as_deref()
            .unwrap_or("")
            .contains("inner")
    );
    // 只有 .so 需要网络:调试文件一次、按需可执行镜像一次。
    assert_eq!(
        server.count("debuginfo"),
        1,
        "主程序用本地文件,.so 恰好一次调试文件请求"
    );
    assert_eq!(server.count("executable"), 1);
}

/// P1-3:按缺失的展开信息决定可执行镜像回退。
/// 场景 A:服务端只归档可执行镜像(无调试文件)——原始 ELF 的
/// `.eh_frame` 仍应提供 CFI 回溯;场景 B:调试文件来自本地符号目录,
/// 可执行镜像只在远程。
#[test]
fn executable_only_server_still_unwinds() {
    if !have_tools() {
        eprintln!("缺少 gcc/objcopy/strip,跳过可执行镜像回退测试");
        return;
    }
    let dir = fixture_dir("exeonly");
    build_fixture(&dir, None);
    let dump = dir.join("crash.dmp");
    produce_minidump(&dir.join("crasher"), &dump);
    fs::create_dir_all(dir.join("empty")).unwrap();

    let lib_bid = elf_build_id(&dir.join("libcrash.so"));
    let served_exe_only = || {
        let mut served = Served::default();
        served.files.insert(
            "executable".to_string(),
            std::collections::HashMap::from([(lib_bid.clone(), dir.join("libcrash.so"))]),
        );
        served
    };

    // 场景 A:本地无产物,服务端只有可执行镜像。
    let server = FakeDebuginfod::start(Arc::new(served_exe_only()));
    let cache = dir.join("cache-a");
    let opts = AnalyzeOptions {
        symbol_paths: vec![dir.join("empty")],
        debuginfod_urls: vec![server.url.clone()],
        cache_dir: cache.clone(),
        ..base_options(vec![], &cache)
    };
    let report = run_analyze(&dump, &opts);
    let lib = report
        .modules
        .iter()
        .find(|m| m.name == "libcrash.so")
        .unwrap();
    assert!(
        matches!(lib.debuginfo, ArtifactStatus::NotArchived { .. }),
        "无调试文件:{:?}",
        lib.debuginfo
    );
    assert!(matches!(lib.executable, ArtifactStatus::Ok { .. }));
    match &lib.symbols {
        SymbolStatus::Loaded {
            has_cfi, has_lines, ..
        } => {
            assert!(has_cfi, "可执行镜像的 .eh_frame 应提供 CFI");
            assert!(!has_lines, "没有调试文件时不应有行号");
        }
        other => panic!("符号应加载:{other:?}"),
    }
    let thread = &report.threads[report.crashing_thread.unwrap()];
    assert!(
        thread.frames.len() > 1,
        "即使缺少行号也应能用 CFI 回溯出更多帧"
    );
    assert!(thread.frames.iter().any(|f| f.trust == "cfi"));
    assert_eq!(server.count("executable"), 1);
    assert_eq!(server.count("debuginfo"), 0);

    // 场景 B:调试文件在本地符号目录,可执行镜像只在远程。
    let debug_dir = dir.join("debugonly");
    fs::create_dir_all(&debug_dir).unwrap();
    fs::copy(
        dir.join("libcrash.so.debug"),
        debug_dir.join("libcrash.so.debug"),
    )
    .unwrap();
    let server_b = FakeDebuginfod::start(Arc::new(served_exe_only()));
    let cache_b = dir.join("cache-b");
    let opts_b = AnalyzeOptions {
        symbol_paths: vec![debug_dir],
        debuginfod_urls: vec![server_b.url.clone()],
        cache_dir: cache_b.clone(),
        ..base_options(vec![], &cache_b)
    };
    let report_b = run_analyze(&dump, &opts_b);
    let lib_b = report_b
        .modules
        .iter()
        .find(|m| m.name == "libcrash.so")
        .unwrap();
    match &lib_b.debuginfo {
        ArtifactStatus::Ok { origin, .. } => assert!(
            matches!(origin, ArtifactOrigin::SymbolPath { .. }),
            "调试文件应来自本地:{origin:?}"
        ),
        other => panic!("调试文件应来自本地:{other:?}"),
    }
    assert!(
        matches!(lib_b.executable, ArtifactStatus::Ok { .. }),
        "{:?}",
        lib_b.executable
    );
    match &lib_b.symbols {
        SymbolStatus::Loaded {
            has_cfi, has_lines, ..
        } => {
            assert!(has_cfi, "远程镜像应补齐本地调试文件缺失的 CFI");
            assert!(has_lines);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(server_b.count("executable"), 1);
}

/// P2-8:含空格、非 ASCII 与保留字符的源码路径应按路径段百分号编码后
/// 请求 `/source` 端点并取回文件(固件目录名自带中文与 `<>&`)。
#[test]
fn source_fetch_percent_encodes_special_paths() {
    if !have_tools() {
        eprintln!("缺少 gcc/objcopy/strip,跳过源码编码测试");
        return;
    }
    // tag 含空格;模板自带 `<崩溃&样本>`。
    let dir = fixture_dir("src fetch");
    build_fixture(&dir, None);
    let dump = dir.join("crash.dmp");
    produce_minidump(&dir.join("crasher"), &dump);

    let mut served = Served::default();
    let register = |served: &mut Served, bid: String, path: PathBuf| {
        let key = path.to_string_lossy().trim_start_matches('/').to_string();
        served.sources.entry(bid).or_default().insert(key, path);
    };
    register(
        &mut served,
        elf_build_id(&dir.join("libcrash.so")),
        dir.join("libcrash.c"),
    );
    register(
        &mut served,
        elf_build_id(&dir.join("crasher")),
        dir.join("main.c"),
    );
    let server = FakeDebuginfod::start(Arc::new(served));

    // 符号走本地;源码未授权本地读取,只能经 /source 端点(P1-4)。
    let cache = dir.join("cache");
    let opts = AnalyzeOptions {
        symbol_paths: vec![dir.clone()],
        debuginfod_urls: vec![server.url.clone()],
        cache_dir: cache.clone(),
        ..base_options(vec![], &cache)
    };
    let report = run_analyze(&dump, &opts);
    let src = report
        .sources
        .iter()
        .find(|s| s.path.ends_with("libcrash.c"))
        .expect("应有 libcrash.c 源码条目");
    assert!(
        matches!(src.status, SourceStatus::Embedded { .. }),
        "{:?}",
        src.status
    );
    assert!(
        src.lines
            .as_ref()
            .unwrap()
            .iter()
            .any(|l| l.contains("CRASH_POINT"))
    );
    assert!(
        server.count("source") >= 1,
        "特殊字符路径应成功请求 /source 端点"
    );
}

// ---------------------------------------------------------------------------
// 第二轮复核回归(R2)
// ---------------------------------------------------------------------------

/// 把 dump 副本中指定模块的 CodeView 记录改写为历史 Breakpad PDB70
/// 格式:GUID 取原 ELF Build ID 的前 16 字节,Age 0。模拟旧 Linux
/// Breakpad 写出的 dump(其 code_identifier 是时间戳+镜像大小)。
fn patch_module_cv_to_pdb70(dump: &Path, module_leaf: &str, out: &Path) {
    let mut bytes = fs::read(dump).unwrap();
    let rd_u32 = |b: &[u8], off: usize| u32::from_le_bytes(b[off..off + 4].try_into().unwrap());
    assert_eq!(&bytes[0..4], b"MDMP", "应为 minidump 文件");
    let num_streams = rd_u32(&bytes, 8) as usize;
    let dir_rva = rd_u32(&bytes, 12) as usize;

    // 目录项:StreamType u32 + Location{DataSize u32, Rva u32}。
    let mut list_rva = None;
    for i in 0..num_streams {
        let e = dir_rva + i * 12;
        if rd_u32(&bytes, e) == 4 {
            // ModuleListStream。
            list_rva = Some(rd_u32(&bytes, e + 8) as usize);
        }
    }
    let list = list_rva.expect("dump 应含模块列表流");

    // MINIDUMP_MODULE 布局:BaseOfImage u64 | SizeOfImage/CheckSum/
    // TimeDateStamp/ModuleNameRva 各 u32(偏移 8..24)| VS_FIXEDFILEINFO
    // 52 字节(24..76)| CvRecord{DataSize,Rva}(76..84)| 其余。
    // 注意:位置描述符在本格式中是 DataSize 在前、Rva 在后。
    const MODULE_SIZE: usize = 108;
    let count = rd_u32(&bytes, list) as usize;
    for i in 0..count {
        let m = list + 4 + i * MODULE_SIZE;
        let name_rva = rd_u32(&bytes, m + 20) as usize;
        let name_len = rd_u32(&bytes, name_rva) as usize;
        let name_utf16: Vec<u16> = bytes[name_rva + 4..name_rva + 4 + name_len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        if !String::from_utf16_lossy(&name_utf16).ends_with(module_leaf) {
            continue;
        }
        let old_size = rd_u32(&bytes, m + 76) as usize;
        let old_rva = rd_u32(&bytes, m + 80) as usize;
        assert!(old_size >= 20, "原 CodeView 记录应含 Build ID");
        // PDB70:RSDS 签名 + 原 Build ID 前 16 字节(GUID 布局逐字节相同,
        // 保证 DebugId 不变)+ Age 0 + 空路径。
        let mut record = Vec::with_capacity(25);
        record.extend_from_slice(&0x5344_5352u32.to_le_bytes()); // "RSDS"
        record.extend_from_slice(&bytes[old_rva + 4..old_rva + 20]);
        record.extend_from_slice(&0u32.to_le_bytes());
        record.push(0);
        let new_rva = bytes.len() as u32;
        bytes.extend_from_slice(&record);
        bytes[m + 76..m + 80].copy_from_slice(&(record.len() as u32).to_le_bytes());
        bytes[m + 80..m + 84].copy_from_slice(&new_rva.to_le_bytes());
        fs::write(out, &bytes).unwrap();
        return;
    }
    panic!("dump 中未找到模块 {module_leaf}");
}

/// R2-P1:旧 Linux Breakpad 的 PDB70 记录承载截短 GUID,其
/// code_identifier(时间戳+大小)不是 Build ID;GUID 相同的同一 `.debug`
/// 应仍能按前缀匹配加载,行号与 CFI 均可用。
#[test]
fn legacy_pdb70_module_still_matches_artifacts() {
    if !have_tools() {
        eprintln!("缺少 gcc/objcopy/strip,跳过 PDB70 兼容测试");
        return;
    }
    let dir = fixture_dir("pdb70");
    let (crash_line, _) = build_fixture(&dir, None);
    let dump = dir.join("crash.dmp");
    produce_minidump(&dir.join("crasher"), &dump);

    let patched = dir.join("crash-pdb70.dmp");
    patch_module_cv_to_pdb70(&dump, "libcrash.so", &patched);

    // 符号目录提供正确的 .debug 与剥离镜像(与未打补丁的 dump 相同)。
    let report = run_analyze(
        &patched,
        &base_options(vec![dir.clone()], &dir.join("cache")),
    );

    let lib = report
        .modules
        .iter()
        .find(|m| m.name == "libcrash.so")
        .expect("应有 libcrash.so 模块");
    assert!(
        matches!(lib.debuginfo, ArtifactStatus::Ok { .. }),
        "PDB70 历史记录应按 GUID 前缀匹配 .debug:{:?}",
        lib.debuginfo
    );
    match &lib.symbols {
        SymbolStatus::Loaded {
            has_cfi, has_lines, ..
        } => {
            assert!(has_cfi);
            assert!(has_lines);
        }
        other => panic!("libcrash 符号应加载:{other:?}"),
    }
    let thread = &report.threads[report.crashing_thread.unwrap()];
    let frame0 = &thread.frames[0];
    assert!(
        frame0.function.as_deref().unwrap_or("").contains("inner"),
        "{:?}",
        frame0.function
    );
    assert_eq!(frame0.line, Some(crash_line));
    // 现代 ELF 完整 ID 不同即拒绝的行为由 wrong_build_id_elf_is_rejected
    // 与单元测试覆盖。
}

/// R2-P1:符号目录只有剥离后的发布物(无 DWARF)时,不得因本地命中
/// 而跳过远程;独立 `.debug` 仍应从 debuginfod 拉取,本地镜像继续
/// 提供展开。CFI、函数与行号都应可用。
#[test]
fn stripped_local_elf_still_fetches_remote_debuginfo() {
    if !have_tools() {
        eprintln!("缺少 gcc/objcopy/strip,跳过剥离镜像远程调试文件测试");
        return;
    }
    let dir = fixture_dir("stripped");
    let (crash_line, _) = build_fixture(&dir, None);
    let dump = dir.join("crash.dmp");
    produce_minidump(&dir.join("crasher"), &dump);

    // 符号目录只放剥离后的发布物。
    let stripped_dir = dir.join("stripped-only");
    fs::create_dir_all(&stripped_dir).unwrap();
    for name in ["crasher", "libcrash.so"] {
        fs::copy(dir.join(name), stripped_dir.join(name)).unwrap();
    }

    // 服务端归档正确的独立 .debug。
    let mut served = Served::default();
    served.files.insert(
        "debuginfo".to_string(),
        std::collections::HashMap::from([(
            elf_build_id(&dir.join("libcrash.so")),
            dir.join("libcrash.so.debug"),
        )]),
    );
    let server = FakeDebuginfod::start(Arc::new(served));

    let cache = dir.join("cache");
    let opts = AnalyzeOptions {
        symbol_paths: vec![stripped_dir],
        debuginfod_urls: vec![server.url.clone()],
        cache_dir: cache.clone(),
        ..base_options(vec![], &cache)
    };
    let report = run_analyze(&dump, &opts);

    let lib = report
        .modules
        .iter()
        .find(|m| m.name == "libcrash.so")
        .unwrap();
    match &lib.debuginfo {
        ArtifactStatus::Ok { origin, .. } => assert!(
            matches!(origin, ArtifactOrigin::Debuginfod { .. }),
            "缺少 DWARF 的本地命中不应阻断远程 .debug:{origin:?}"
        ),
        other => panic!("应从服务端获取调试文件:{other:?}"),
    }
    assert!(
        matches!(lib.executable, ArtifactStatus::Ok { .. }),
        "本地剥离镜像保留用于展开:{:?}",
        lib.executable
    );
    match &lib.symbols {
        SymbolStatus::Loaded {
            has_cfi, has_lines, ..
        } => {
            assert!(has_cfi, "本地镜像提供 CFI");
            assert!(has_lines, "远程 .debug 提供行号");
        }
        other => panic!("{other:?}"),
    }
    let thread = &report.threads[report.crashing_thread.unwrap()];
    assert!(
        thread.frames[0]
            .function
            .as_deref()
            .unwrap_or("")
            .contains("inner")
    );
    assert_eq!(thread.frames[0].line, Some(crash_line));
    assert_eq!(
        server.count("debuginfo"),
        1,
        "本地剥离命中后仍应请求一次远程 .debug"
    );

    // 第二次分析:本地剥离镜像不再遮蔽缓存,命中上次下载的 .debug。
    let report2 = run_analyze(&dump, &opts);
    let lib2 = report2
        .modules
        .iter()
        .find(|m| m.name == "libcrash.so")
        .unwrap();
    assert!(matches!(lib2.debuginfo, ArtifactStatus::Ok { .. }));
    assert!(matches!(lib2.symbols, SymbolStatus::Loaded { .. }));
    assert_eq!(
        server.count("debuginfo"),
        1,
        "第二次分析应命中缓存,不重复下载"
    );
}

/// R2-P2:源码服务出错(503)时继续尝试备用服务器与已授权的本地目录,
/// 所有来源都失败才报告获取错误。
#[test]
fn source_fetch_falls_back_on_server_error() {
    if !have_tools() {
        eprintln!("缺少 gcc/objcopy/strip,跳过源码备用来源测试");
        return;
    }
    let dir = fixture_dir("srcfail");
    build_fixture(&dir, None);
    let dump = dir.join("crash.dmp");
    produce_minidump(&dir.join("crasher"), &dump);

    // 源码归档:libcrash.c(lib 的 Build ID)。
    let mut served_ok = Served::default();
    let lib_bid = elf_build_id(&dir.join("libcrash.so"));
    let lib_src = dir.join("libcrash.c");
    served_ok.sources.insert(
        lib_bid.clone(),
        std::collections::HashMap::from([(
            lib_src
                .to_string_lossy()
                .trim_start_matches('/')
                .to_string(),
            lib_src.clone(),
        )]),
    );
    // 故障服务:所有 /source 请求返回 503。
    let failing = FakeDebuginfod::start(Arc::new(Served {
        sources_always_error: true,
        ..Default::default()
    }));

    // 1. 首个来源 503,第二个来源有文件 → 嵌入成功。
    let backup = FakeDebuginfod::start(Arc::new(served_ok));
    let cache = dir.join("cache");
    let opts = AnalyzeOptions {
        symbol_paths: vec![dir.clone()],
        debuginfod_urls: vec![failing.url.clone(), backup.url.clone()],
        cache_dir: cache.clone(),
        ..base_options(vec![], &cache)
    };
    let report = run_analyze(&dump, &opts);
    let src = report
        .sources
        .iter()
        .find(|s| s.path.ends_with("libcrash.c"))
        .expect("应有 libcrash.c 源码条目");
    assert!(
        matches!(src.status, SourceStatus::Embedded { .. }),
        "服务出错后应继续尝试备用来源:{:?}",
        src.status
    );
    assert!(
        src.lines
            .as_ref()
            .unwrap()
            .iter()
            .any(|l| l.contains("CRASH_POINT"))
    );
    assert_eq!(backup.count("source"), 1, "备用服务器应收到源码请求");

    // 2. 唯一的来源持续出错,本地源码根目录已授权 → 离线嵌入。
    let failing2 = FakeDebuginfod::start(Arc::new(Served {
        sources_always_error: true,
        ..Default::default()
    }));
    let cache2 = dir.join("cache2");
    let opts2 = AnalyzeOptions {
        symbol_paths: vec![dir.clone()],
        debuginfod_urls: vec![failing2.url.clone()],
        cache_dir: cache2.clone(),
        source_roots: vec![dir.clone()],
        ..base_options(vec![], &cache2)
    };
    let report2 = run_analyze(&dump, &opts2);
    let src2 = report2
        .sources
        .iter()
        .find(|s| s.path.ends_with("libcrash.c"))
        .expect("应有 libcrash.c 源码条目");
    assert!(
        matches!(src2.status, SourceStatus::Embedded { .. }),
        "服务出错后应回退到获准的本地源码:{:?}",
        src2.status
    );

    // 3. 唯一的来源出错且未授权本地目录 → 保留获取失败诊断。
    let failing3 = FakeDebuginfod::start(Arc::new(Served {
        sources_always_error: true,
        ..Default::default()
    }));
    let cache3 = dir.join("cache3");
    let opts3 = AnalyzeOptions {
        symbol_paths: vec![dir.clone()],
        debuginfod_urls: vec![failing3.url.clone()],
        cache_dir: cache3.clone(),
        ..base_options(vec![], &cache3)
    };
    let report3 = run_analyze(&dump, &opts3);
    let src3 = report3
        .sources
        .iter()
        .find(|s| s.path.ends_with("libcrash.c"))
        .expect("应有 libcrash.c 源码条目");
    assert!(
        matches!(src3.status, SourceStatus::FetchFailed { .. }),
        "所有来源失败时报告获取错误:{:?}",
        src3.status
    );
}

// ---------------------------------------------------------------------------
// CLI 冒烟测试
// ---------------------------------------------------------------------------

#[test]
fn cli_analyze_writes_reports() {
    if !have_tools() {
        eprintln!("缺少 gcc/objcopy/strip,跳过 CLI 测试");
        return;
    }
    let dir = fixture_dir("cli");
    build_fixture(&dir, None);
    let dump = dir.join("crash.dmp");
    produce_minidump(&dir.join("crasher"), &dump);

    let html = dir.join("report.html");
    let json = dir.join("report.json");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_zminidump"))
        .arg("analyze")
        .arg(&dump)
        .arg("--html")
        .arg(&html)
        .arg("--json")
        .arg(&json)
        .arg("--symbol-path")
        .arg(&dir)
        .arg("--source-root")
        .arg(&dir)
        .arg("--cache")
        .arg(dir.join("cache"))
        .arg("--no-debuginfod")
        .arg("--include-source=context")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "CLI 应成功:{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let html_text = fs::read_to_string(&html).unwrap();
    assert!(html_text.contains("<!DOCTYPE html>"));
    assert!(html_text.contains("崩溃分析报告"));
    assert!(
        !html_text.contains("e2e-cli-<崩溃&样本>"),
        "HTML 必须转义路径"
    );
    // 获准的本地源码(--source-root)离线嵌入。
    assert!(
        html_text.contains("CRASH_POINT"),
        "授权源码根目录后应嵌入固件源码"
    );
    let json_text = fs::read_to_string(&json).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json_text).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert!(!v["threads"].as_array().unwrap().is_empty());
}

/// P1-5:输出与输入 dump 指向同一文件(含别名)时命令必须失败,
/// 原始 dump 字节保持一致;HTML 与 JSON 指向同一目标时同样拒绝。
#[test]
fn cli_refuses_to_overwrite_dump_or_sibling_report() {
    if !have_tools() {
        eprintln!("缺少 gcc/objcopy/strip,跳过输出冲突测试");
        return;
    }
    let dir = fixture_dir("conflict");
    build_fixture(&dir, None);
    let dump = dir.join("crash.dmp");
    produce_minidump(&dir.join("crasher"), &dump);
    let before = fs::read(&dump).unwrap();

    let base = || {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_zminidump"));
        cmd.arg("analyze")
            .arg(&dump)
            .arg("--symbol-path")
            .arg(&dir)
            .arg("--cache")
            .arg(dir.join("cache"))
            .arg("--no-debuginfod");
        cmd
    };

    // 1. --json 指向输入 dump 本体。
    let out = base().arg("--json").arg(&dump).output().unwrap();
    assert!(!out.status.success(), "JSON 输出与输入 dump 同文件必须失败");
    assert_eq!(
        fs::read(&dump).unwrap(),
        before,
        "原始 dump 字节必须保持一致"
    );

    // 2. --html 指向输入 dump(以 `..` 别名形式)。
    let alias = format!("{}/./crash.dmp", dir.display());
    let out = base().arg("--html").arg(&alias).output().unwrap();
    assert!(
        !out.status.success(),
        "HTML 输出与输入 dump 同文件(路径别名)必须失败"
    );
    assert_eq!(fs::read(&dump).unwrap(), before);

    // 3. --html 与 --json 指向同一目标。
    let target = dir.join("same.out");
    let out = base()
        .arg("--html")
        .arg(&target)
        .arg("--json")
        .arg(&target)
        .output()
        .unwrap();
    assert!(!out.status.success(), "HTML 与 JSON 输出同文件必须失败");
    assert!(!target.exists(), "不得写出任何报告");
    assert_eq!(fs::read(&dump).unwrap(), before);

    // 4. --json 指向输入 dump 的硬链接(不同路径名,同一 inode)。
    let hard_json = dir.join("hard-json.out");
    std::fs::hard_link(&dump, &hard_json).unwrap();
    let out = base().arg("--json").arg(&hard_json).output().unwrap();
    assert!(!out.status.success(), "输出与输入互为硬链接必须失败");
    assert_eq!(
        fs::read(&dump).unwrap(),
        before,
        "硬链接目标(即输入)字节必须保持一致"
    );

    // 5. 两个输出互为硬链接。
    let h1 = dir.join("out-a.html");
    let h2 = dir.join("out-b.json");
    std::fs::write(&h1, b"").unwrap();
    std::fs::hard_link(&h1, &h2).unwrap();
    let out = base()
        .arg("--html")
        .arg(&h1)
        .arg("--json")
        .arg(&h2)
        .output()
        .unwrap();
    assert!(!out.status.success(), "两个输出互为硬链接必须失败");
    assert_eq!(fs::read(&dump).unwrap(), before);
    assert_eq!(fs::read(&h1).unwrap(), b"", "硬链接输出不得被写入");
}

/// 供调试测试使用。
pub fn produce_minidump_pub(crasher: &Path, dump_path: &Path) {
    produce_minidump(crasher, dump_path);
}
