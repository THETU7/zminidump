//! Zminidump 核心:本地原生崩溃分析。
//!
//! 输入 Breakpad/Crashpad `.dmp`,按模块 Build ID 查找调试产物
//! (用户指定 → `--symbol-path` 扫描 → 缓存 → debuginfod),展开栈并
//! 生成版本化报告,导出为可离线浏览的单文件 HTML 或 JSON。

pub mod analyze;
pub mod artifacts;
pub mod debuginfod;
pub mod html;
pub mod report;
pub mod source;
pub mod symbols;
pub mod util;

pub use analyze::{AnalyzeOptions, analyze_dump};
pub use report::{Report, SourceMode};

/// JSON 导出。
pub fn render_json(report: &Report) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}
