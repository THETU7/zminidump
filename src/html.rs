//! 单文件 HTML 报告渲染。
//!
//! - 样式随 HTML 内嵌;使用浏览器原生 `<details>` 折叠与页内锚点,
//!   打开报告无需启动服务或联网。
//! - 崩溃线程默认展开;栈扫描帧标记为候选。
//! - 帧可跳转到模块记录或带行号的源码。
//! - 所有来自 dump 或调试产物的文本一律转义。

use crate::report::*;
use crate::util::escape_html;
use std::fmt::Write as _;

const CSS: &str = r#"
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font: 14px/1.5 system-ui, "Segoe UI", "Noto Sans CJK SC", sans-serif;
       margin: 0; padding: 1rem 1.5rem 4rem; max-width: 1200px; }
h1 { font-size: 1.35rem; margin: 0.2em 0; }
h2 { font-size: 1.1rem; margin: 1.6em 0 0.5em; border-bottom: 1px solid color-mix(in srgb, currentColor 15%, transparent); padding-bottom: 0.25em; }
.meta { color: color-mix(in srgb, currentColor 65%, transparent); font-size: 0.9em; }
.card { border: 1px solid color-mix(in srgb, currentColor 20%, transparent); border-radius: 8px;
        padding: 0.75rem 1rem; margin: 0.75rem 0; background: color-mix(in srgb, currentColor 4%, transparent); }
.crash { border-color: #c0392b88; }
.crash .reason { font-size: 1.05rem; font-weight: 600; }
.mono, code, pre { font-family: ui-monospace, "JetBrains Mono", Consolas, monospace; }
table { border-collapse: collapse; width: 100%; margin: 0.4rem 0; }
th, td { text-align: left; padding: 0.25rem 0.5rem; vertical-align: top;
         border-bottom: 1px solid color-mix(in srgb, currentColor 10%, transparent); }
th { font-weight: 600; color: color-mix(in srgb, currentColor 70%, transparent); white-space: nowrap; }
td.num { text-align: right; white-space: nowrap; }
.badge { display: inline-block; border-radius: 4px; padding: 0 0.35em; font-size: 0.82em;
         border: 1px solid color-mix(in srgb, currentColor 35%, transparent); }
.badge.scan { border-style: dashed; color: #b8860b; }
.badge.ctx  { color: #c0392b; }
.badge.cfi, .badge.fp { color: #2e7d32; }
details { margin: 0.4rem 0; }
details > summary { cursor: pointer; padding: 0.3rem 0.2rem; }
details[open] > summary { font-weight: 600; }
.muted { color: color-mix(in srgb, currentColor 55%, transparent); }
.ok    { color: #2e7d32; }
.bad   { color: #c0392b; }
.warn  { color: #b8860b; }
pre.src { overflow-x: auto; border: 1px solid color-mix(in srgb, currentColor 15%, transparent);
          border-radius: 6px; padding: 0.5rem 0; margin: 0.25rem 0; font-size: 0.85rem; }
.src .ln { display: inline-block; width: 4.5em; padding-right: 0.75em; text-align: right;
           color: color-mix(in srgb, currentColor 45%, transparent); user-select: none; }
.src .gap { color: color-mix(in srgb, currentColor 40%, transparent); padding-left: 1rem; }
.src .hl:target { background: #b8860b33; outline: 1px solid #b8860b66; }
.registers { columns: 4; }
.registers div { break-inside: avoid; }
footer { margin-top: 2.5rem; color: color-mix(in srgb, currentColor 55%, transparent); font-size: 0.85em; }
a { color: inherit; }
.addr, .offset { white-space: nowrap; }
"#;

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
        escape_html(&dump_leaf(&report.dump_path))
    );
    let _ = writeln!(html, "<style>{CSS}</style></head><body>");

    render_header(&mut html, report);
    render_threads(&mut html, report);
    render_modules(&mut html, report);
    render_sources(&mut html, report);
    render_footer(&mut html, report);

    let _ = writeln!(html, "</body></html>");
    html
}

fn dump_leaf(path: &str) -> String {
    crate::util::basename(path)
}

fn render_header(html: &mut String, report: &Report) {
    let _ = writeln!(html, "<h1>崩溃分析报告</h1>");
    let _ = writeln!(
        html,
        "<p class=\"meta\">输入:<span class=\"mono\">{}</span> · 工具 {} {} · 报告结构 v{}</p>",
        escape_html(&report.dump_path),
        escape_html(&report.tool_name),
        escape_html(&report.tool_version),
        report.schema_version
    );

    if let Some(exception) = &report.exception {
        let _ = writeln!(html, "<div class=\"card crash\">");
        let _ = writeln!(
            html,
            "<div class=\"reason\">{} <span class=\"mono muted\">@ {}</span></div>",
            escape_html(&exception.reason),
            escape_html(&exception.address)
        );
        let thread_desc = report
            .crashing_thread
            .and_then(|i| report.threads.get(i))
            .map(|t| format!("线程 {} {}", t.thread_id, name_suffix(t)))
            .unwrap_or_else(|| "未知线程".into());
        let _ = writeln!(html, "<div>崩溃线程:{}</div>", escape_html(&thread_desc));
        let _ = writeln!(html, "</div>");
    } else {
        let _ = writeln!(
            html,
            "<div class=\"card\"><div>该 dump 未包含异常记录(可能是主动触发的转储)。</div></div>"
        );
    }

    let _ = writeln!(html, "<div class=\"card\">");
    let sys = &report.system;
    let _ = writeln!(
        html,
        "<div>系统:{} {} · CPU:{}{}</div>",
        escape_html(&sys.os),
        escape_html(sys.os_version.as_deref().unwrap_or("")),
        escape_html(&sys.cpu),
        sys.cpu_info
            .as_deref()
            .map(|c| format!("({c})"))
            .unwrap_or_default()
            .pipe_escape()
    );
    if let Some(time) = report.crash_time {
        let _ = writeln!(html, "<div>崩溃时间(UNIX 秒):{time}</div>");
    }
    if let Some(pid) = report.process_id {
        let _ = writeln!(html, "<div>进程 PID:{pid}</div>");
    }
    let _ = writeln!(html, "</div>");

    // 崩溃线程寄存器。
    if let Some(t) = report.crashing_thread.and_then(|i| report.threads.get(i))
        && let Some(regs) = &t.registers
    {
        let _ = writeln!(
            html,
            "<details><summary>崩溃线程寄存器</summary><div class=\"registers mono\">"
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

fn name_suffix(t: &ThreadReport) -> String {
    t.name
        .as_deref()
        .map(|n| format!("({n})"))
        .unwrap_or_default()
}

trait PipeEscape {
    fn pipe_escape(self) -> String;
}
impl PipeEscape for String {
    fn pipe_escape(self) -> String {
        escape_html(&self)
    }
}

fn render_threads(html: &mut String, report: &Report) {
    let _ = writeln!(html, "<h2 id=\"threads\">线程与调用栈</h2>");
    for (i, thread) in report.threads.iter().enumerate() {
        let is_crash = Some(i) == report.crashing_thread;
        let open = if is_crash { " open" } else { "" };
        let crash_mark = if is_crash { " ⚠ 崩溃线程" } else { "" };
        let _ = writeln!(
            html,
            "<details{open}><summary>线程 {tid} {name} — {n} 帧{crash_mark}</summary>",
            tid = thread.thread_id,
            name = escape_html(&name_suffix(thread)),
            n = thread.frames.len(),
        );
        if let Some(info) = &thread.info {
            let _ = writeln!(html, "<p class=\"warn\">⚠ {}</p>", escape_html(info));
        }
        let _ = writeln!(
            html,
            "<table><thead><tr><th>#</th><th>信任</th><th>模块</th><th class=\"num\">指令地址</th><th class=\"num\">偏移</th><th>函数</th><th>文件:行</th></tr></thead><tbody>"
        );
        for frame in &thread.frames {
            render_frame_row(html, frame, report);
        }
        let _ = writeln!(html, "</tbody></table></details>");
    }
}

fn render_frame_row(html: &mut String, frame: &FrameReport, _report: &Report) {
    let (badge_class, badge_text) = match frame.trust.as_str() {
        "context" => ("ctx", "上下文"),
        "cfi" => ("cfi", "CFI"),
        "frame_pointer" => ("fp", "帧指针"),
        "scan" => ("scan", "候选(栈扫描)"),
        other => ("", other),
    };
    let module_html = frame
        .module_index
        .map(|mi| {
            format!(
                "<a href=\"#module-{mi}\">{}</a>",
                escape_html(&_module_name(_report, mi))
            )
        })
        .unwrap_or_else(|| "<span class=\"muted\">??</span>".to_string());

    let func = frame
        .function
        .as_deref()
        .map(escape_html)
        .unwrap_or_else(|| "<span class=\"muted\">??</span>".to_string());
    let func_full = match (&frame.function, &frame.function_offset) {
        (Some(_), Some(off)) => format!("{func}<span class=\"muted\"> +{off}</span>"),
        _ => func,
    };
    let file_html = render_file_line(
        frame.file.as_deref(),
        frame.line,
        frame.source_anchor.as_ref(),
    );

    // 绝对指令地址始终展示:模块归属与偏移都可能为空(例如加密主程序
    // 的指令落入匿名映射),报告浏览者需要帧地址做手工核对。
    let _ = writeln!(
        html,
        "<tr><td class=\"num\">{i}</td><td><span class=\"badge {bc}\">{bt}</span></td><td>{module}</td><td class=\"mono addr\">{addr}</td><td class=\"mono offset\">{off}</td><td class=\"mono\">{func}</td><td class=\"mono\">{file}</td></tr>",
        i = frame.index,
        bc = badge_class,
        bt = badge_text,
        module = module_html,
        addr = escape_html(&frame.instruction),
        off = frame.offset.as_deref().map(escape_html).unwrap_or_default(),
        func = func_full,
        file = file_html,
    );

    // 内联帧行。
    for inline in &frame.inlines {
        let ifunc = inline
            .function
            .clone()
            .map(|f| escape_html(&f))
            .unwrap_or_else(|| "<span class=\"muted\">??</span>".to_string());
        let ifile = render_file_line(
            inline.file.as_deref(),
            inline.line,
            inline.source_anchor.as_ref(),
        );
        let _ = writeln!(
            html,
            "<tr class=\"muted\"><td class=\"num\">·</td><td>↳ 内联</td><td></td><td></td><td></td><td class=\"mono\">{}</td><td class=\"mono\">{}</td></tr>",
            ifunc, ifile
        );
    }
}

fn _module_name(report: &Report, index: usize) -> String {
    report
        .modules
        .get(index)
        .map(|m| m.name.clone())
        .unwrap_or_default()
}

fn render_file_line(
    file: Option<&str>,
    line: Option<u32>,
    anchor: Option<&SourceAnchor>,
) -> String {
    match (file, line) {
        (Some(file), Some(line)) => match anchor {
            // 链接目标用锚点行号(已收敛到实际嵌入的行区间),
            // 显示文本保留原始行号。
            Some(a) => format!(
                "<a href=\"#src-{}-L{}\">{}</a>",
                a.source_index,
                a.line,
                escape_html(&format!("{file}:{line}"))
            ),
            None => escape_html(&format!("{file}:{line}")),
        },
        (Some(file), None) => escape_html(file),
        (None, _) => "<span class=\"muted\">??</span>".to_string(),
    }
}

fn render_modules(html: &mut String, report: &Report) {
    let _ = writeln!(html, "<h2 id=\"modules\">模块</h2>");
    let _ = writeln!(
        html,
        "<table><thead><tr><th>名称</th><th>Build ID</th><th>Debug ID</th><th class=\"num\">基址·大小</th><th>产物状态</th><th>符号</th></tr></thead><tbody>"
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
    let _ = writeln!(html, "</tbody></table>");
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

fn render_sources(html: &mut String, report: &Report) {
    let _ = writeln!(html, "<h2 id=\"sources\">源码</h2>");
    if report.source_mode == SourceMode::None {
        let _ = writeln!(
            html,
            "<p class=\"muted\">源码嵌入已关闭(<code>--include-source=none</code>)。使用 <code>--include-source=context|full</code> 可在导出时嵌入源码片段。</p>"
        );
        return;
    }
    if report.sources.is_empty() {
        let _ = writeln!(html, "<p class=\"muted\">调用栈没有引用带行号的源码。</p>");
        return;
    }
    if report.source_omitted_count > 0 {
        let _ = writeln!(
            html,
            "<p class=\"warn\">⚠ 因源码总大小上限({} 字节)省略了 {} 个文件。</p>",
            report.source_max_bytes, report.source_omitted_count
        );
    }
    for source in &report.sources {
        let status_html = match &source.status {
            SourceStatus::Embedded { bytes } => {
                format!("<span class=\"ok\">已嵌入({bytes} 字节)</span>")
            }
            SourceStatus::Disabled => "<span class=\"muted\">未启用</span>".into(),
            SourceStatus::NotArchived => "<span class=\"warn\">服务端未归档</span>".into(),
            SourceStatus::NotFound => "<span class=\"warn\">未找到</span>".into(),
            SourceStatus::FetchFailed { message } => {
                format!(
                    "<span class=\"bad\">获取失败:{}</span>",
                    escape_html(message)
                )
            }
            SourceStatus::SizeCapped => "<span class=\"warn\">超出大小上限,已省略</span>".into(),
        };
        let _ = writeln!(
            html,
            "<details><summary><span class=\"mono\">{}</span> {}</summary>",
            escape_html(&source.path),
            status_html
        );
        if let Some(lines) = &source.lines {
            let ranges = source.line_ranges.clone().unwrap_or_default();
            let _ = writeln!(html, "<pre class=\"src\">");
            let mut cursor = 0usize;
            for (ri, range) in ranges.iter().enumerate() {
                if ri > 0 {
                    let _ = writeln!(html, "<span class=\"gap\">⋯</span>");
                }
                for l in range.0..=range.1 {
                    let text = lines.get(cursor).cloned().unwrap_or_default();
                    cursor += 1;
                    let _ = writeln!(
                        html,
                        "<span class=\"hl\" id=\"src-{i}-L{l}\"><span class=\"ln\">{l}</span>{}</span>",
                        escape_html(&text),
                        i = source.index
                    );
                }
            }
            let _ = writeln!(html, "</pre>");
        }
        let _ = writeln!(html, "</details>");
    }
}

fn render_footer(html: &mut String, report: &Report) {
    let _ = writeln!(html, "<footer>");
    let _ = writeln!(
        html,
        "<p>报告由 {} {} 生成,可离线浏览;未内嵌原始 dump、二进制或凭据。补齐产物后可用原始 dump 重新分析。</p>",
        escape_html(&report.tool_name),
        escape_html(&report.tool_version)
    );
    let _ = writeln!(
        html,
        "<p>展开来源图例:上下文 = 异常寄存器,CFI = 调用帧信息,帧指针 = RBP 链,候选(栈扫描) = 扫描结果,仅供参考。</p>"
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
                    function_offset: None,
                    file: Some("/src/a<b>&c.c".into()),
                    line: Some(3),
                    inlines: vec![InlineFrameReport {
                        function: Some("in&line".into()),
                        file: Some("/src/i.c".into()),
                        line: Some(4),
                        source_anchor: None,
                    }],
                    source_anchor: None,
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
                status: SourceStatus::Disabled,
                lines: Some(vec!["l1 <b>".into(), "l2 &".into(), "l3".into()]),
                line_ranges: Some(vec![(1, 3)]),
            }],
            source_mode: SourceMode::Context,
            source_omitted_count: 0,
            source_max_bytes: 10,
        };
        let html = render_html(&report);
        // 原始尖括号不应以未转义形式出现在动态文本中。
        assert!(!html.contains("/src/a<b>&c.c"));
        assert!(html.contains("/src/a&lt;b&gt;&amp;c.c"));
        assert!(!html.contains("fn<&x>"));
        assert!(html.contains("候选(栈扫描)"));
        assert!(html.contains("id=\"module-0\""));
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
