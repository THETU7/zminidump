//! 离线 HTML 报告。调用栈与源码共用一个浏览区，所有样式、交互与源码均内嵌。

use crate::report::*;
use crate::util::{basename, escape_html};
use std::fmt::Write as _;

mod highlight;

const CSS: &str = include_str!("html/report.css");
const SCRIPT: &str = include_str!("html/report.js");

/// 渲染完整 HTML 报告。
pub fn render_html(report: &Report) -> String {
    let mut html = String::with_capacity(64 * 1024);
    let _ = writeln!(html, "<!DOCTYPE html>");
    let _ = writeln!(html, "<html lang=\"zh-CN\"><head><meta charset=\"utf-8\">");
    let _ = writeln!(
        html,
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
    );
    let _ = writeln!(
        html,
        "<title>{} 崩溃报告 — {}</title>",
        escape_html(&report.tool_name),
        escape_html(&basename(&report.dump_path))
    );
    let _ = writeln!(html, "<style>{CSS}</style></head><body>");

    let _ = writeln!(html, "<main class=\"report\">");
    render_header(&mut html, report);
    render_stack(&mut html, report);
    render_modules(&mut html, report);
    render_footer(&mut html, report);

    let _ = writeln!(html, "</main><script>{SCRIPT}</script></body></html>");
    html
}

fn render_header(html: &mut String, report: &Report) {
    let _ = writeln!(
        html,
        r##"<header class="report-header"><div class="topbar"><span class="brand mono">{}</span><nav aria-label="报告导航"><a href="#threads">调用栈</a><a href="#modules">模块</a></nav></div><h1>崩溃分析报告</h1><p class="dump-path mono">{}</p></header>"##,
        escape_html(&report.tool_name),
        escape_html(&report.dump_path)
    );

    let crash_thread = report.crashing_thread.and_then(|i| report.threads.get(i));
    let _ = writeln!(
        html,
        r##"<div class="overview card"><div class="overview-event">"##
    );
    if let Some(exception) = &report.exception {
        let _ = writeln!(
            html,
            r##"<span class="badge ctx">崩溃线程 {}{}</span><h2 class="exception mono">{}</h2><p class="meta">异常地址 <code>{}</code></p>"##,
            exception.thread_id,
            crash_thread
                .and_then(|t| t.name.as_deref())
                .map(|name| format!(" · {}", escape_html(name)))
                .unwrap_or_default(),
            escape_html(&exception.reason),
            escape_html(&exception.address)
        );
    } else {
        let _ = writeln!(html, r##"<h2 class="exception">未记录异常</h2>"##);
    }
    let _ = writeln!(html, r##"</div><dl class="system">"##);
    let sys = &report.system;
    let _ = writeln!(
        html,
        "<div><dt>系统</dt><dd>{} {}</dd></div><div><dt>CPU</dt><dd>{}{}</dd></div>",
        escape_html(&sys.os),
        escape_html(sys.os_version.as_deref().unwrap_or("")),
        escape_html(&sys.cpu),
        sys.cpu_info
            .as_deref()
            .map(|info| format!(" ({})", escape_html(info)))
            .unwrap_or_default()
    );
    if let Some(time) = report.crash_time {
        let _ = writeln!(
            html,
            "<div><dt>崩溃时间（UNIX 秒）</dt><dd>{time}</dd></div>"
        );
    }
    if let Some(pid) = report.process_id {
        let _ = writeln!(html, "<div><dt>进程 PID</dt><dd>{pid}</dd></div>");
    }
    let _ = writeln!(html, "</dl></div>");

    if !report.notes.is_empty() {
        let _ = writeln!(html, r##"<ul class="notice warn">"##);
        for note in &report.notes {
            let _ = writeln!(html, "<li>{}</li>", escape_html(note));
        }
        let _ = writeln!(html, "</ul>");
    }

    if let Some(regs) = crash_thread.and_then(|t| t.registers.as_ref()) {
        let _ = writeln!(
            html,
            r##"<details class="card registers"><summary>崩溃线程寄存器</summary><div class="register-grid mono">"##
        );
        for (name, value) in regs {
            let _ = writeln!(
                html,
                "<div>{} = {}</div>",
                escape_html(name),
                escape_html(value)
            );
        }
        let _ = writeln!(html, "</div></details>");
    }
}

fn render_stack(html: &mut String, report: &Report) {
    let _ = writeln!(
        html,
        r##"<section class="section" aria-labelledby="threads"><div class="section-heading"><h2 id="threads">调用栈</h2><span class="meta">{} 个线程</span></div>"##,
        report.threads.len()
    );
    if report.threads.is_empty() {
        let _ = writeln!(
            html,
            r##"<p class="card empty">该转储没有线程记录。</p></section>"##
        );
        return;
    }

    let _ = writeln!(
        html,
        r##"<div class="workspace"><div class="thread-list">"##
    );
    let crash = report.crashing_thread.filter(|&i| i < report.threads.len());
    let indices = crash
        .into_iter()
        .chain((0..report.threads.len()).filter(|&i| Some(i) != crash));
    for (position, index) in indices.enumerate() {
        let thread = &report.threads[index];
        let open = if position == 0 { " open" } else { "" };
        let crash_badge = if Some(index) == crash {
            r##"<span class="badge ctx">崩溃</span>"##
        } else {
            ""
        };
        let name = thread
            .name
            .as_deref()
            .filter(|name| !name.is_empty())
            .map(|name| {
                format!(
                    r##"<span class="thread-name">{}</span>"##,
                    escape_html(name)
                )
            })
            .unwrap_or_default();
        let _ = writeln!(
            html,
            r##"<details class="thread card"{open}><summary><span class="thread-label">线程 {tid}{name}{crash_badge}</span><span class="meta frame-count">{count} 帧</span></summary>"##,
            tid = thread.thread_id,
            count = thread.frames.len(),
        );
        if let Some(info) = &thread.info {
            let _ = writeln!(
                html,
                r##"<p class="thread-note warn">{}</p>"##,
                escape_html(info)
            );
        }
        if thread.frames.is_empty() {
            let _ = writeln!(html, r##"<p class="empty">此线程没有可用的栈帧。</p>"##);
        } else {
            let _ = writeln!(html, r##"<ol class="frames" role="list">"##);
            for frame in &thread.frames {
                render_frame(html, frame, report);
            }
            let _ = writeln!(html, "</ol>");
        }
        let _ = writeln!(html, "</details>");
    }
    let _ = writeln!(html, r##"</div><div class="source-slot">"##);
    render_source_preview(html, report);
    let _ = writeln!(html, "</div></div></section>");
}

fn render_frame(html: &mut String, frame: &FrameReport, report: &Report) {
    let badge = match frame.trust.as_str() {
        "context" => ("ctx", "上下文"),
        "cfi" => ("cfi", "CFI"),
        "frame_pointer" => ("fp", "帧指针"),
        "scan" => ("scan", "候选(栈扫描)"),
        other => ("", other),
    };
    let module = frame
        .module_index
        .and_then(|index| report.modules.get(index));
    let mut function = frame.function.as_deref().unwrap_or("未知函数").to_owned();
    if let (Some(_), Some(offset)) = (&frame.function, &frame.function_offset) {
        let _ = write!(function, " +{offset}");
    }

    let _ = writeln!(html, r##"<li class="frame"><div class="frame-entry">"##);
    render_frame_link(
        html,
        &function,
        &format!("#{}", frame.index),
        badge,
        frame_source(
            report,
            module,
            frame.file.as_deref(),
            frame.line,
            frame.source_anchor.as_ref(),
        ),
    );
    let _ = write!(html, r##"<div class="frame-meta mono">"##);
    if let Some(module) = module {
        let _ = write!(
            html,
            r##"<a href="#module-{}">{}</a>"##,
            module.index,
            escape_html(&module.name)
        );
    }
    // 即使没有模块和偏移，绝对指令地址仍可用于手工定位。
    let _ = write!(
        html,
        r##"<span title="指令地址">{}</span>"##,
        escape_html(&frame.instruction)
    );
    if let Some(offset) = &frame.offset {
        let _ = write!(
            html,
            r##"<span title="模块偏移">+{}</span>"##,
            escape_html(offset)
        );
    }
    let _ = writeln!(html, "</div></div>");

    if !frame.inlines.is_empty() {
        let _ = writeln!(html, r##"<ol class="inlines" role="list">"##);
        for inline in &frame.inlines {
            let _ = writeln!(html, r##"<li><div class="frame-entry">"##);
            render_frame_link(
                html,
                inline.function.as_deref().unwrap_or("未知函数"),
                "↳",
                ("inline", "内联"),
                frame_source(
                    report,
                    module,
                    inline.file.as_deref(),
                    inline.line,
                    inline.source_anchor.as_ref(),
                ),
            );
            let _ = writeln!(html, "</div></li>");
        }
        let _ = writeln!(html, "</ol>");
    }
    let _ = writeln!(html, "</li>");
}

struct FrameSource {
    href: String,
    location: String,
    short_location: String,
    message: String,
}

fn frame_source(
    report: &Report,
    module: Option<&ModuleReport>,
    file: Option<&str>,
    line: Option<u32>,
    anchor: Option<&SourceAnchor>,
) -> FrameSource {
    let location = |file: &str| match line {
        Some(line) => format!("{file}:{line}"),
        None => file.to_owned(),
    };
    let mut source = FrameSource {
        href: "#source-preview".into(),
        location: file.map(location).unwrap_or_default(),
        short_location: file
            .map(|file| location(&basename(file)))
            .unwrap_or_default(),
        message: String::new(),
    };
    if let Some(anchor) = anchor {
        source.href = format!("#src-{}-L{}", anchor.source_index, anchor.line);
    } else if let (Some(file), Some(_)) = (file, line) {
        let build_id = module.and_then(|m| m.build_id.as_deref());
        let file = report
            .sources
            .iter()
            .find(|s| s.path == file && s.build_id.as_deref() == build_id);
        source.message = match file {
            Some(file) if matches!(file.status, SourceStatus::Embedded { .. }) => {
                if file.lines.as_ref().is_some_and(|lines| !lines.is_empty()) {
                    source.href = format!("#source-{}", file.index);
                }
                "该行未嵌入".into()
            }
            Some(file) => source_status(&file.status).1,
            None if report.source_mode == SourceMode::None => {
                source_status(&SourceStatus::Disabled).1
            }
            None => "此帧的源码不可用。".into(),
        };
    } else {
        source.message = "此帧没有可用的文件行号。".into();
    }
    source
}

fn render_frame_link(
    html: &mut String,
    function: &str,
    number: &str,
    (badge_class, badge): (&str, &str),
    source: FrameSource,
) {
    let _ = write!(
        html,
        r##"<a class="frame-link" href="{}" aria-controls="source-preview" data-location="{}" data-source-message="{}"><span class="frame-number mono">{number}</span><span class="frame-description"><span class="frame-function mono">{}</span>"##,
        source.href,
        escape_html(&source.location),
        escape_html(&source.message),
        escape_html(function)
    );
    if !source.short_location.is_empty() {
        let _ = write!(
            html,
            r##"<span class="frame-location mono" title="{}">{}</span>"##,
            escape_html(&source.location),
            escape_html(&source.short_location)
        );
    }
    let _ = writeln!(
        html,
        r##"</span><span class="badge {badge_class}">{}</span></a>"##,
        escape_html(badge)
    );
}

fn render_modules(html: &mut String, report: &Report) {
    let _ = writeln!(
        html,
        "<section class=\"section\" aria-labelledby=\"modules\"><div class=\"section-heading\"><h2 id=\"modules\">模块</h2><span class=\"meta\">{} 个模块</span></div>",
        report.modules.len()
    );
    if report.modules.is_empty() {
        let _ = writeln!(
            html,
            "<p class=\"card empty\">该转储没有模块记录。</p></section>"
        );
        return;
    }
    let _ = writeln!(
        html,
        "<div class=\"module-table card\" tabindex=\"0\" aria-label=\"模块列表\">"
    );
    let _ = writeln!(
        html,
        "<table><thead><tr><th>名称</th><th>Build ID</th><th>Debug ID</th><th>基址与大小</th><th>产物状态</th><th>符号</th></tr></thead><tbody>"
    );
    for module in &report.modules {
        let _ = writeln!(html, "<tr id=\"module-{index}\">", index = module.index);
        let _ = writeln!(
            html,
            "<td class=\"mono\" title=\"{code}\">{name}</td>",
            code = escape_html(&module.code_file),
            name = escape_html(&module.name)
        );
        let _ = writeln!(
            html,
            "<td class=\"mono\">{}</td>",
            module
                .build_id
                .as_deref()
                .map(escape_html)
                .unwrap_or_else(|| "<span class=\"muted\">—</span>".into())
        );
        let _ = writeln!(
            html,
            "<td class=\"mono\">{}</td>",
            module
                .debug_id
                .as_deref()
                .map(escape_html)
                .unwrap_or_else(|| "<span class=\"muted\">—</span>".into())
        );
        let _ = writeln!(
            html,
            "<td class=\"mono\">{} · {:#x}</td>",
            escape_html(&module.base_address),
            module.size
        );
        let _ = writeln!(html, "<td>{}</td>", render_artifacts(module));
        let _ = writeln!(html, "<td>{}</td>", render_symbols(module));
        let _ = writeln!(html, "</tr>");
    }
    let _ = writeln!(html, "</tbody></table></div></section>");
}

fn render_artifacts(module: &ModuleReport) -> String {
    let fmt = |label: &str, status: &ArtifactStatus| {
        let (class, text) = if status.is_ok() {
            ("ok", "✓")
        } else {
            ("bad", "✗")
        };
        format!(
            "<div>{} <span class=\"{class}\">{}</span> <span class=\"muted\">{}</span></div>",
            label,
            text,
            escape_html(&status.describe())
        )
    };
    format!(
        "{}{}",
        fmt("可执行:", &module.executable),
        fmt("调试文件:", &module.debuginfo)
    )
}

fn render_symbols(module: &ModuleReport) -> String {
    match &module.symbols {
        SymbolStatus::Loaded {
            detail,
            has_cfi,
            has_lines,
        } => {
            let mut tags = String::new();
            tags.push_str(if *has_cfi { "CFI ✓ " } else { "CFI ✗ " });
            tags.push_str(if *has_lines {
                "行号 ✓"
            } else {
                "行号 ✗"
            });
            format!(
                "<span class=\"ok\">已加载</span> <span class=\"muted\">{}</span><br><span class=\"muted\">{}</span>",
                escape_html(&tags),
                escape_html(detail)
            )
        }
        SymbolStatus::Corrupt { detail, message } => format!(
            "<span class=\"bad\">损坏</span> <span class=\"muted\">{} {}</span>",
            escape_html(detail),
            escape_html(message)
        ),
        SymbolStatus::Missing { reason } => format!(
            "<span class=\"warn\">缺失</span> <span class=\"muted\">{}</span>",
            escape_html(reason)
        ),
    }
}

fn source_status(status: &SourceStatus) -> (&'static str, String) {
    match status {
        SourceStatus::Embedded { bytes } => ("ok", format!("已嵌入（{bytes} 字节）")),
        SourceStatus::Disabled => ("muted", "源码嵌入已关闭。".into()),
        SourceStatus::NotArchived => ("warn", "服务端未归档此文件。".into()),
        SourceStatus::NotFound => ("warn", "未找到此文件的源码。".into()),
        SourceStatus::FetchFailed { message } => ("bad", format!("源码获取失败（{message}）")),
        SourceStatus::SizeCapped => ("warn", "此文件超出源码总大小上限，已省略。".into()),
    }
}

fn render_source_preview(html: &mut String, report: &Report) {
    let _ = writeln!(
        html,
        r##"<aside class="source-panel card" id="source-preview" aria-labelledby="source-heading"><header class="source-header"><h3 id="source-heading">源码</h3><p id="source-location" class="mono" hidden></p></header>"##
    );
    let prompt = match report.source_mode {
        SourceMode::None => "源码嵌入已关闭（<code>--include-source=none</code>）。",
        _ if report.sources.is_empty() => "调用栈没有引用带行号的源码。",
        _ => "选择栈帧查看对应源码。",
    };
    let _ = writeln!(
        html,
        r##"<p id="source-message" class="empty">{prompt}</p>"##
    );
    if report.source_omitted_count > 0 {
        let _ = writeln!(
            html,
            r##"<p class="source-limit warn">达到源码总大小上限（{} 字节），省略了 {} 个文件。</p>"##,
            report.source_max_bytes, report.source_omitted_count
        );
    }
    for source in &report.sources {
        let (class, status) = source_status(&source.status);
        let _ = writeln!(
            html,
            r##"<details class="source-file" id="source-{}"><summary><span class="mono">{}</span> <span class="{class}">{}</span></summary>"##,
            source.index,
            escape_html(&source.path),
            escape_html(&status)
        );
        if let (Some(lines), Some(ranges)) = (&source.lines, &source.line_ranges)
            && !lines.is_empty()
        {
            let _ = write!(
                html,
                r##"<pre class="src" tabindex="0" aria-label="源码内容"><code>"##
            );
            let mut lines = lines.iter();
            let mut highlighter = highlight::Highlighter::new(&source.path);
            for (i, &(start, end)) in ranges.iter().enumerate() {
                if i > 0 {
                    let _ = write!(html, r##"<span class="gap">⋯</span>"##);
                    highlighter.reset();
                }
                for (line, code) in (start..=end).zip(&mut lines) {
                    let _ = write!(
                        html,
                        r##"<span class="source-line" id="src-{index}-L{line}"><span class="ln" aria-hidden="true">{line}</span>"##,
                        index = source.index
                    );
                    highlighter.render_line(html, code);
                    html.push_str("</span>");
                }
            }
            let _ = writeln!(html, "</code></pre>");
        }
        let _ = writeln!(html, "</details>");
    }
    let _ = writeln!(html, "</aside>");
}

fn render_footer(html: &mut String, report: &Report) {
    let _ = writeln!(html, "<footer>");
    let _ = writeln!(
        html,
        "<p>{} {} · 报告结构 v{} · 离线报告</p>",
        escape_html(&report.tool_name),
        escape_html(&report.tool_version),
        report.schema_version
    );
    let _ = writeln!(
        html,
        "<p>展开来源：上下文（异常寄存器）、CFI（调用帧信息）、帧指针（RBP 链）、候选（栈扫描，仅供参考）。</p>"
    );
    let _ = writeln!(html, "</footer>");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_everywhere() {
        let report = crate::report::Report {
            schema_version: 1,
            tool_name: "z<minidump>".into(),
            tool_version: "0.1".into(),
            dump_path: "/tmp/<x> & \"y'.dmp".into(),
            crash_time: Some(1),
            process_id: Some(7),
            exception: Some(ExceptionReport {
                reason: "EXCEPTION_<TAG>".into(),
                address: "0x0".into(),
                thread_id: 1,
            }),
            crashing_thread: Some(0),
            system: SystemReport {
                os: "Linux".into(),
                cpu: "x86_64".into(),
                cpu_info: None,
                os_version: None,
            },
            threads: vec![ThreadReport {
                thread_id: 1,
                name: Some("<main>".into()),
                info: None,
                frames: vec![FrameReport {
                    index: 0,
                    instruction: "0x1000".into(),
                    offset: Some("0x10".into()),
                    module_index: Some(0),
                    trust: "scan".into(),
                    is_candidate: true,
                    function: Some("fn<&x>".into()),
                    function_offset: Some("<offset>".into()),
                    file: Some("/src/a<b>&c.c".into()),
                    line: Some(3),
                    inlines: vec![InlineFrameReport {
                        function: Some("in&line".into()),
                        file: Some("/src/a<b>&c.c".into()),
                        line: Some(2),
                        source_anchor: Some(SourceAnchor {
                            source_index: 0,
                            line: 2,
                        }),
                    }],
                    source_anchor: Some(SourceAnchor {
                        source_index: 0,
                        line: 3,
                    }),
                }],
                registers: Some(
                    [("rax".to_string(), "0x0".to_string())]
                        .into_iter()
                        .collect(),
                ),
            }],
            modules: vec![ModuleReport {
                index: 0,
                name: "a<b>.so".into(),
                code_file: "/lib/a<b>.so".into(),
                debug_file: None,
                base_address: "0xff0".into(),
                size: 1,
                debug_id: None,
                build_id: None,
                code_id: None,
                version: None,
                executable: ArtifactStatus::NoSource,
                debuginfo: ArtifactStatus::NoSource,
                symbols: SymbolStatus::Missing {
                    reason: "<原因>".into(),
                },
            }],
            sources: vec![SourceFileReport {
                index: 0,
                path: "/src/a<b>&c.c".into(),
                build_id: None,
                status: SourceStatus::Embedded { bytes: 21 },
                lines: Some(vec!["l1 <b>".into(), "</script>".into(), "l3".into()]),
                line_ranges: Some(vec![(1, 3)]),
            }],
            notes: Vec::new(),
            source_mode: SourceMode::Context,
            source_omitted_count: 0,
            source_max_bytes: 10,
        };
        let html = render_html(&report);
        // 原始尖括号不应以未转义形式出现在动态文本中。
        assert!(!html.contains("/src/a<b>&c.c"));
        assert!(html.contains("/src/a&lt;b&gt;&amp;c.c"));
        assert!(!html.contains("fn<&x>"));
        assert!(html.contains("fn&lt;&amp;x&gt; +&lt;offset&gt;"));
        assert!(html.contains(r##"href="#src-0-L2""##));
        assert!(html.contains(r##"href="#src-0-L3""##));
        assert!(html.contains("id=\"src-0-L2\""));
        assert!(html.contains("&lt;/script&gt;"));
        assert_eq!(html.matches("</script>").count(), 1);
        assert!(html.contains("候选(栈扫描)"));
        assert!(html.contains("id=\"module-0\""));
    }

    /// R3-P2:行号超出嵌入源码内容时不生成链接,保留原始文件与行号
    /// 并提示该行不可用;已嵌入的行正常链接。
    #[test]
    fn html_marks_out_of_range_source_lines() {
        let frame = |line: Option<u32>, anchor: Option<SourceAnchor>| FrameReport {
            index: 0,
            instruction: "0x1000".into(),
            offset: None,
            module_index: Some(0),
            trust: "cfi".into(),
            is_candidate: false,
            function: Some("fn".into()),
            function_offset: None,
            file: Some("/src/short.c".into()),
            line,
            inlines: vec![],
            source_anchor: anchor,
        };
        let report = Report {
            schema_version: 1,
            tool_name: "t".into(),
            tool_version: "0".into(),
            dump_path: "/tmp/x.dmp".into(),
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
                // 帧 0:行 1 已嵌入(带锚点);帧 1:行 28 越界(无锚点)。
                frames: vec![
                    frame(
                        Some(1),
                        Some(SourceAnchor {
                            source_index: 0,
                            line: 1,
                        }),
                    ),
                    frame(Some(28), None),
                ],
                registers: None,
            }],
            modules: vec![],
            sources: vec![SourceFileReport {
                index: 0,
                path: "/src/short.c".into(),
                build_id: None,
                status: SourceStatus::Embedded { bytes: 16 },
                lines: Some(vec!["only line".into()]),
                line_ranges: Some(vec![(1, 1)]),
            }],
            notes: Vec::new(),
            source_mode: SourceMode::Context,
            source_omitted_count: 0,
            source_max_bytes: 1024,
        };

        let html = render_html(&report);
        // 已嵌入的行正常链接。
        assert!(html.contains("href=\"#src-0-L1\""));
        // 越界行保留原始位置和提示，链接只打开文件，不定位其他行。
        assert!(html.contains("/src/short.c:28"), "应保留原始行号");
        assert!(html.contains("该行未嵌入"), "应提示该行不可用");
        assert!(html.contains(
            r##"href="#source-0" aria-controls="source-preview" data-location="/src/short.c:28""##
        ));
        assert!(!html.contains("href=\"#src-0-L28\""));
    }

    /// P2-9:HTML 栈帧必须显示绝对指令地址;无模块归属(偏移为空)的
    /// 帧在 JSON 与 HTML 两种导出里都能查到同一个地址。
    #[test]
    fn html_shows_absolute_instruction_address() {
        let report = crate::report::Report {
            schema_version: 1,
            tool_name: "t".into(),
            tool_version: "0".into(),
            dump_path: "/tmp/x.dmp".into(),
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
                frames: vec![FrameReport {
                    index: 0,
                    instruction: "0x7f01a2b3c4d5".into(),
                    // 加密主程序的帧可能没有模块归属,偏移为空。
                    offset: None,
                    module_index: None,
                    trust: "context".into(),
                    is_candidate: false,
                    function: None,
                    function_offset: None,
                    file: None,
                    line: None,
                    inlines: vec![],
                    source_anchor: None,
                }],
                registers: None,
            }],
            modules: vec![],
            sources: vec![],
            notes: Vec::new(),
            source_mode: SourceMode::None,
            source_omitted_count: 0,
            source_max_bytes: 0,
        };

        // JSON 一侧始终有 `instruction` 字段。
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(
            json["threads"][0]["frames"][0]["instruction"],
            "0x7f01a2b3c4d5"
        );
        // HTML 一侧也要能查到同一绝对地址。
        let html = render_html(&report);
        assert!(
            html.contains("0x7f01a2b3c4d5"),
            "HTML 栈帧应显示绝对指令地址"
        );
    }
}
