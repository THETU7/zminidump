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

use zminidump::report::{ArtifactStatus, SourceMode, SymbolStatus};
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

    let report = run_analyze(&dump, &base_options(vec![dir.clone()], &dir.join("cache")));

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

/// kind(debuginfo/executable)→ build_id → 文件。
type ServedFiles = std::collections::HashMap<String, std::collections::HashMap<String, PathBuf>>;

impl FakeDebuginfod {
    fn start(files: Arc<ServedFiles>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let hit_counter = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let files = files.clone();
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
    files: Arc<ServedFiles>,
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
    // /buildid/{id}/{kind}
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    if segments.len() == 3 && segments[0] == "buildid" {
        let (id, kind) = (segments[1], segments[2]);
        let hit = files
            .get(kind)
            .and_then(|m| m.get(id))
            .and_then(|f| fs::read(f).ok());
        if let Some(bytes) = hit {
            *hits.lock().unwrap().entry(kind.to_string()).or_insert(0) += 1;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            );
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(&bytes).unwrap();
            return;
        }
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
    let mut files: ServedFiles = std::collections::HashMap::new();
    for (kind, suffix) in [("debuginfo", ".debug"), ("executable", "")] {
        let mut per_kind = std::collections::HashMap::new();
        for name in ["crasher", "libcrash.so"] {
            let path = dir.join(format!("{name}{suffix}"));
            per_kind.insert(elf_build_id(&path), path);
        }
        files.insert(kind.to_string(), per_kind);
    }
    let server = FakeDebuginfod::start(Arc::new(files));

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
    let json_text = fs::read_to_string(&json).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json_text).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert!(!v["threads"].as_array().unwrap().is_empty());
}

/// 供调试测试使用。
pub fn produce_minidump_pub(crasher: &Path, dump_path: &Path) {
    produce_minidump(crasher, dump_path);
}
