//! 版本化报告模型,HTML 与 JSON 导出共用。
//!
//! 设计要求至少记录:异常、崩溃线程、模块 ID、帧地址及偏移、展开来源、
//! 函数、内联帧、文件行号和产物状态;符号、展开和源码各自保留诊断结果。

use serde::{Deserialize, Serialize};

/// 报告结构版本。不兼容变更时递增。
pub const REPORT_SCHEMA_VERSION: u32 = 1;

pub const TOOL_NAME: &str = env!("CARGO_PKG_NAME");
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// 源码嵌入模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SourceMode {
    /// 仅显示路径和行号(默认)。
    #[default]
    None,
    /// 嵌入关键帧附近的源码片段。
    Context,
    /// 嵌入调用栈引用的完整源文件。
    Full,
}

impl SourceMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceMode::None => "none",
            SourceMode::Context => "context",
            SourceMode::Full => "full",
        }
    }
}

/// 产物(ELF 可执行文件或独立调试文件)的获取来源。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum ArtifactOrigin {
    /// 用户在命令行显式指定的文件。
    UserSpecified { path: String },
    /// 在 `--symbol-path` 目录中扫描到的文件。
    SymbolPath { path: String },
    /// 之前下载后留在缓存中的文件。
    Cache { path: String },
    /// 本次从 debuginfod 下载并已写入缓存。
    Debuginfod { server: String, path: String },
}

/// 单个产物(模块的可执行文件或调试文件)的状态。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ArtifactStatus {
    /// 找到并通过 Build ID 核验。
    Ok {
        origin: ArtifactOrigin,
        /// 从产物核验出的完整 GNU Build ID(小写十六进制)。
        build_id: String,
        /// 产物是否携带 DWARF 调试信息。
        has_debug_info: bool,
    },
    /// 候选文件存在但 Build ID 不匹配,已拒绝。
    IdentityMismatch {
        path: String,
        expected: String,
        found: String,
    },
    /// 服务器明确返回未归档(404)。
    NotArchived { server: String },
    /// 下载或读取失败(网络、权限、损坏等)。
    FetchFailed { server: String, message: String },
    /// dump 中该模块缺少可用于查找的身份标识。
    MissingIdentity,
    /// 未配置任何能提供该产物的来源。
    NoSource,
}

impl ArtifactStatus {
    pub fn is_ok(&self) -> bool {
        matches!(self, ArtifactStatus::Ok { .. })
    }

    /// 面向报告展示的简短说明。
    pub fn describe(&self) -> String {
        match self {
            ArtifactStatus::Ok { origin, .. } => match origin {
                ArtifactOrigin::UserSpecified { path }
                | ArtifactOrigin::SymbolPath { path }
                | ArtifactOrigin::Cache { path } => format!("已匹配({})", path),
                ArtifactOrigin::Debuginfod { server, .. } => {
                    format!("已下载并缓存({server})")
                }
            },
            ArtifactStatus::IdentityMismatch { path, .. } => {
                format!("Build ID 不匹配,已拒绝({path})")
            }
            ArtifactStatus::NotArchived { server } => format!("服务端未归档({server})"),
            ArtifactStatus::FetchFailed { server, message } => {
                format!("获取失败({server}):{message}")
            }
            ArtifactStatus::MissingIdentity => "模块缺少 Build ID".to_string(),
            ArtifactStatus::NoSource => "无可用来源".to_string(),
        }
    }
}

/// 模块的符号化状态与诊断。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SymbolStatus {
    /// 成功加载符号(预生成 .sym 或从 ELF 生成)。
    Loaded {
        /// 符号来源描述。
        detail: String,
        /// 是否包含 CFI 展开规则。
        has_cfi: bool,
        /// 是否包含 DWARF 行号信息。
        has_lines: bool,
    },
    /// 找到符号但解析失败。
    Corrupt { detail: String, message: String },
    /// 没有可用符号。
    Missing { reason: String },
}

/// 源码文件在报告中的获取状态。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SourceStatus {
    /// 已嵌入报告。
    Embedded { bytes: usize },
    /// 未嵌入(当前模式为 none)。
    Disabled,
    /// 服务器未归档该源码。
    NotArchived,
    /// 本地与服务端均未找到。
    NotFound,
    /// 获取失败。
    FetchFailed { message: String },
    /// 因总大小上限被省略。
    SizeCapped,
}

/// 内联帧(按由内到外排序)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineFrameReport {
    pub function: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    /// 嵌入源码后的锚点,用于 HTML 跳转。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_anchor: Option<SourceAnchor>,
}

/// 单个物理栈帧(内联帧单独记录在其 `inlines` 中)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameReport {
    /// 展示序号(含内联帧展开后的全局序号)。
    pub index: usize,
    /// 帧所在指令的绝对虚拟地址。
    pub instruction: String,
    /// 相对模块基址的偏移;无模块归属时为 `None`。
    pub offset: Option<String>,
    /// 帧所属模块在 `Report::modules` 中的下标。
    pub module_index: Option<usize>,
    /// 展开来源(context / cfi / frame_pointer / scan / …)。
    pub trust: String,
    /// 栈扫描得到的候选帧标记。
    pub is_candidate: bool,
    pub function: Option<String>,
    /// 相对函数起始地址的偏移。
    pub function_offset: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    /// 内联帧,由内到外。
    pub inlines: Vec<InlineFrameReport>,
    /// 嵌入源码后的锚点(文件 id + 行号),用于 HTML 跳转。
    pub source_anchor: Option<SourceAnchor>,
}

/// 源码锚点:`src-<file>-<line>` 页内链接目标。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceAnchor {
    pub source_index: usize,
    pub line: u32,
}

/// 单个线程的展开结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadReport {
    pub thread_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// 展开诊断(例如缺少栈内存导致的中断原因)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<String>,
    pub frames: Vec<FrameReport>,
    /// 崩溃线程顶部帧的通用寄存器(十六进制字符串)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registers: Option<std::collections::BTreeMap<String, String>>,
}

/// 模块记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleReport {
    pub index: usize,
    /// 文件名(路径最后一段)。
    pub name: String,
    pub code_file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_file: Option<String>,
    /// 模块基址。
    pub base_address: String,
    pub size: u64,
    /// Breakpad Debug ID(GUID+Age)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_id: Option<String>,
    /// Linux 上为完整 GNU Build ID(小写十六进制);dump 只带截短标识时,
    /// 可由匹配产物补全。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    /// Code ID(Windows PE 镜像的 Code ID 等)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub executable: ArtifactStatus,
    pub debuginfo: ArtifactStatus,
    pub symbols: SymbolStatus,
}

/// 嵌入的源码文件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFileReport {
    pub index: usize,
    /// 符号化得到的文件路径(通常为 comp_dir 拼接后的绝对路径)。
    pub path: String,
    /// 提供该源码的模块 Build ID(debuginfod /source 端点使用)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    pub status: SourceStatus,
    /// 嵌入的行号内容(1 起始);仅在嵌入时存在。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines: Option<Vec<String>>,
    /// 该文件在报告中实际嵌入的行区间(context 模式下为合并后的片段)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_ranges: Option<Vec<(u32, u32)>>,
}

/// 异常信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionReport {
    /// 人类可读的崩溃原因,例如 `EXCEPTION_ACCESS_VIOLATION_READ`。
    pub reason: String,
    /// 触发异常的地址。
    pub address: String,
    /// 崩溃线程 ID。
    pub thread_id: u32,
}

/// 系统信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemReport {
    pub os: String,
    pub cpu: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
}

/// 完整分析报告。HTML 与 JSON 导出共用此模型。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    /// 工具名与版本。
    pub tool_name: String,
    pub tool_version: String,
    /// 输入 dump 路径。
    pub dump_path: String,
    /// dump 记录的崩溃时间(UNIX 秒)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crash_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception: Option<ExceptionReport>,
    /// `threads` 中崩溃线程的下标。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crashing_thread: Option<usize>,
    pub system: SystemReport,
    pub threads: Vec<ThreadReport>,
    pub modules: Vec<ModuleReport>,
    pub sources: Vec<SourceFileReport>,
    pub source_mode: SourceMode,
    /// 因总大小上限被省略嵌入的文件数。
    pub source_omitted_count: usize,
    /// 源码总嵌入字节上限。
    pub source_max_bytes: u64,
}

impl Report {
    pub fn tool() -> (String, String) {
        (TOOL_NAME.to_string(), TOOL_VERSION.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_is_stable() {
        assert_eq!(REPORT_SCHEMA_VERSION, 1);
    }

    #[test]
    fn source_mode_serde_roundtrip() {
        let m = SourceMode::Context;
        let s = serde_json::to_string(&m).unwrap();
        assert_eq!(s, "\"context\"");
        let back: SourceMode = serde_json::from_str(&s).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn artifact_status_describe_covers_branches() {
        let cases = [
            ArtifactStatus::NoSource,
            ArtifactStatus::MissingIdentity,
            ArtifactStatus::NotArchived {
                server: "https://s".into(),
            },
            ArtifactStatus::FetchFailed {
                server: "https://s".into(),
                message: "timeout".into(),
            },
            ArtifactStatus::IdentityMismatch {
                path: "/x".into(),
                expected: "aa".into(),
                found: "bb".into(),
            },
        ];
        for c in cases {
            assert!(!c.describe().is_empty());
            assert!(!c.is_ok());
        }
    }
}
