//! 调试产物查找:用户指定文件 → `--symbol-path` 本地扫描 → 缓存 → debuginfod。
//!
//! 每个候选 ELF 都必须通过完整 GNU Build ID 核验;dump 只带截短标识
//! (Breakpad Debug ID 的 GUID 部分)时,允许按 GUID 前缀匹配并从产物
//! 补全完整 Build ID。同一来源、同一模块、同一产物类型的并发请求合并。

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use debugid::{CodeId, DebugId};
use memmap2::Mmap;
use minidump::Module;
use object::{Object as _, ObjectSection as _, ObjectSegment as _};
use tokio::{sync::Mutex as AsyncMutex, sync::Semaphore};

use crate::{
    debuginfod::{self, DebuginfodClient, FetchResult},
    report::{ArtifactOrigin, ArtifactStatus, SymbolStatus},
};

/// 产物类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactKind {
    Executable,
    DebugInfo,
}

impl ArtifactKind {
    fn cache_leaf(self) -> &'static str {
        match self {
            ArtifactKind::Executable => "executable",
            ArtifactKind::DebugInfo => "debuginfo",
        }
    }
}

/// 从 minidump 模块记录提取的身份标识。
#[derive(Debug, Clone)]
pub struct ModuleIdentity {
    /// Breakpad Debug ID(ELF 上来自 Build ID 前 16 字节的 GUID)。
    pub debug_id: Option<DebugId>,
    /// Code ID;仅当 CodeView 记录确认其为完整 GNU Build ID 时才可信。
    pub code_id: Option<CodeId>,
    /// code_file 的文件名。
    pub leaf: String,
}

impl ModuleIdentity {
    pub fn from_module(module: &dyn Module) -> Self {
        Self {
            debug_id: module.debug_identifier(),
            code_id: module.code_identifier(),
            leaf: crate::util::basename(&module.code_file()),
        }
    }

    /// 按 dump 的 CodeView 记录类型提取完整 GNU Build ID。
    ///
    /// 只有 ELF 记录的 `code_identifier()` 是完整 Build ID;旧 Linux
    /// Breakpad 用 PDB70 记录承载截短 GUID,其 `code_identifier()` 由
    /// 时间戳和镜像大小组成,不是 Build ID,不得用于完整比较——
    /// 否则 GUID 相同的历史 dump 会被误判为身份不匹配。
    pub fn from_module_with_cv(module: &dyn Module, cv: Option<&minidump::CodeView>) -> Self {
        let mut ident = Self::from_module(module);
        match cv {
            Some(minidump::CodeView::Elf(raw)) if !raw.build_id.iter().all(|b| *b == 0) => {
                ident.code_id = Some(CodeId::new(hex_lower(&raw.build_id)));
            }
            Some(minidump::CodeView::Pdb70(_)) | Some(minidump::CodeView::Pdb20(_)) => {
                // 历史 Breakpad 记录:只有截短 GUID,回退到前缀匹配。
                ident.code_id = None;
            }
            // 无记录(Windows 回退语义)或未知格式:保留 trait 的原始值。
            _ => {}
        }
        ident
    }

    /// 完整 GNU Build ID(小写十六进制),优先取 Code ID。
    pub fn full_build_id(&self) -> Option<String> {
        self.code_id.as_ref().map(|c| c.as_str().to_string())
    }

    /// 状态表的键:同一身份的模块共享产物查找结果。
    pub fn key(&self) -> String {
        match (&self.debug_id, &self.code_id) {
            (_, Some(code)) => format!("code:{}", code.as_str()),
            (Some(debug), None) => format!("debug:{}", debug),
            (None, None) => format!("leaf:{}", self.leaf),
        }
    }
}

/// 从 ELF 文件探测出的元数据。
#[derive(Debug, Clone)]
pub struct ElfMeta {
    /// 完整 GNU Build ID(小写十六进制);无 note 时为 `None`。
    pub build_id: Option<String>,
    pub has_debug_info: bool,
    /// 是否含有可执行段(区分真实镜像与独立调试文件)。
    pub has_exec_segments: bool,
}

/// 探测字节缓冲区中的 ELF;非 ELF 返回 `None`。
pub fn probe_elf_bytes(data: &[u8]) -> Option<ElfMeta> {
    if !matches!(
        object::read::FileKind::parse(data),
        Ok(object::read::FileKind::Elf32 | object::read::FileKind::Elf64)
    ) {
        return None;
    }
    let obj = object::read::File::parse(data).ok()?;
    let build_id = obj.build_id().ok().flatten().map(hex_lower);
    let has_debug_info = obj
        .section_by_name(".debug_info")
        .map(|s| s.size() > 0)
        .unwrap_or(false);
    let has_exec_segments = obj.segments().any(|seg| {
        matches!(
            seg.flags(),
            object::SegmentFlags::Elf { p_type: _, p_flags } if p_flags & object::elf::PF_X == object::elf::PF_X
        ) && seg.data().map(|d| !d.is_empty()).unwrap_or(false)
    });
    Some(ElfMeta {
        build_id,
        has_debug_info,
        has_exec_segments,
    })
}

/// 探测磁盘上的 ELF 文件。
pub fn probe_elf_file(path: &Path) -> Option<ElfMeta> {
    let file = fs::File::open(path).ok()?;
    let map = unsafe { Mmap::map(&file) }.ok()?;
    probe_elf_bytes(&map)
}

pub fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// ELF 与模块身份的匹配结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdMatch {
    /// 完整 Build ID 一致。
    Full,
    /// 仅 GUID(Breakpad Debug ID)一致,dump 带的是截短标识。
    TruncatedGuid,
}

/// 校验 ELF 元数据是否匹配模块身份。
///
/// dump 带完整 Code ID(Linux 上即完整 GNU Build ID)时只做完整比较:
/// 前缀相同但末尾不同的 Build ID 属于不同构建,不得回退到 GUID 前缀
/// 匹配;仅当 dump 缺少完整 ID(只带 Breakpad GUID)时才允许前缀回退。
pub fn match_identity(meta: &ElfMeta, ident: &ModuleIdentity) -> Option<IdMatch> {
    let Some(elf_id) = &meta.build_id else {
        return None;
    };
    let has_full_code_id = ident
        .code_id
        .as_ref()
        .map(|c| !c.as_str().is_empty())
        .unwrap_or(false);
    if has_full_code_id {
        let code = ident.code_id.as_ref().expect("checked above");
        return if elf_id.eq_ignore_ascii_case(code.as_str()) {
            Some(IdMatch::Full)
        } else {
            None
        };
    }
    if let Some(debug) = ident.debug_id
        && guid_matches(elf_id, &debug)
    {
        return Some(IdMatch::TruncatedGuid);
    }
    None
}

/// 判断 Build ID 十六进制串的前 16 字节是否对应给定的 Breakpad Debug ID。
pub fn guid_matches(build_id_hex: &str, debug: &DebugId) -> bool {
    let bytes = match hex_to_bytes(build_id_hex) {
        Some(b) => b,
        None => return false,
    };
    if bytes.len() < 16 {
        return false;
    }
    match debugid::DebugId::from_guid_age(&bytes[..16], 0) {
        Ok(d) => d == *debug,
        Err(_) => false,
    }
}

pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// 本地扫描索引条目:ELF 产物。
#[derive(Debug, Clone)]
pub struct LocalElf {
    pub path: PathBuf,
    pub meta: ElfMeta,
}

/// 本地扫描索引条目:预生成的 Breakpad `.sym`。
#[derive(Debug, Clone)]
pub struct LocalSym {
    pub path: PathBuf,
    /// .sym MODULE 行中的 Debug ID。
    pub debug_id: String,
    /// `INFO CODE_ID` 行中的完整身份;缺失时为 `None`(历史格式)。
    pub code_id: Option<String>,
    pub name: String,
}

/// `--symbol-path` 目录的扫描索引。
#[derive(Debug, Default)]
pub struct LocalIndex {
    elfs: Vec<LocalElf>,
    syms: Vec<LocalSym>,
}

const MAX_SCAN_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 单文件 2 GiB 上限

impl LocalIndex {
    /// 扫描目录,建立 ELF 与 .sym 索引。忽略无法解析的文件。
    pub fn scan(dirs: &[PathBuf]) -> Self {
        let mut index = Self::default();
        for dir in dirs {
            index.walk(dir);
        }
        index
    }

    fn walk(&mut self, dir: &Path) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                self.walk(&entry.path());
                continue;
            }
            if !ft.is_file() && !ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            let Ok(meta) = fs::metadata(&path) else {
                continue;
            };
            if meta.len() > MAX_SCAN_FILE_BYTES || meta.len() == 0 {
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) == Some("sym") {
                if let Some(sym) = probe_sym_file(&path) {
                    self.syms.push(sym);
                }
            } else if let Some(elf) = probe_elf_file(&path) {
                self.elfs.push(LocalElf { path, meta: elf });
            }
        }
    }

    /// 按身份查找 ELF 产物;按产物类型选择最佳候选。
    pub fn find_elf(&self, ident: &ModuleIdentity, kind: ArtifactKind) -> Option<&LocalElf> {
        let mut best: Option<(u32, &LocalElf)> = None;
        for elf in &self.elfs {
            let Some(m) = match_identity(&elf.meta, ident) else {
                continue;
            };
            // 评分:完整匹配优先;按类型偏好调试信息/可执行段。
            let mut score = match m {
                IdMatch::Full => 2,
                IdMatch::TruncatedGuid => 1,
            };
            score *= 10;
            match kind {
                ArtifactKind::DebugInfo => {
                    if elf.meta.has_debug_info {
                        score += 2;
                    }
                }
                ArtifactKind::Executable => {
                    // 独立调试文件没有可执行段,也没有 `.eh_frame`,
                    // 不能充当可执行镜像(否则会错过远程镜像回退)。
                    if !elf.meta.has_exec_segments {
                        continue;
                    }
                    score += 2;
                    if !looks_like_debug_file(&elf.path) {
                        score += 1;
                    }
                }
            }
            if best.map(|(s, _)| score > s).unwrap_or(true) {
                best = Some((score, elf));
            }
        }
        best.map(|(_, e)| e)
    }

    /// 查找文件名相同但 Build ID 不符的 ELF(身份不匹配诊断)。
    pub fn find_conflicting(&self, ident: &ModuleIdentity) -> Option<&LocalElf> {
        self.elfs.iter().find(|e| {
            crate::util::basename(&e.path.to_string_lossy()) == ident.leaf
                && match_identity(&e.meta, ident).is_none()
        })
    }

    /// 按 Breakpad Debug ID 查找预生成 `.sym`。dump 与 `.sym` 都带有
    /// 完整身份(`INFO CODE_ID`)时必须一致:截短 GUID 相同但完整身份
    /// 不同的是另一个构建,其行号与展开规则不得混用;不匹配的候选
    /// 跳过,继续查找其他候选。
    pub fn find_sym(&self, ident: &ModuleIdentity) -> Option<&LocalSym> {
        let debug = ident.debug_id?;
        // .sym 的 MODULE 行使用 Breakpad 格式:无连字符的大写 GUID + Age,
        // 而非 DebugId 的普通显示格式(带连字符 UUID)。
        let wanted = debug.breakpad().to_string();
        let full = ident.full_build_id();
        self.syms.iter().find(|s| {
            if !s.debug_id.eq_ignore_ascii_case(&wanted) {
                return false;
            }
            match (&full, &s.code_id) {
                // 双方都有完整身份:必须一致。
                (Some(want), Some(have)) => have.eq_ignore_ascii_case(want),
                // 历史格式(.sym 或 dump 缺完整身份):保持兼容。
                _ => true,
            }
        })
    }
}

fn looks_like_debug_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e == "debug")
        .unwrap_or(false)
        || path.to_string_lossy().ends_with(".dwo")
}

/// 解析 `.sym` 文件首行 `MODULE <os> <arch> <id> <name>` 及可选的
/// `INFO CODE_ID <id> [<name>]` 行。
fn probe_sym_file(path: &Path) -> Option<LocalSym> {
    use std::io::BufRead;
    let file = fs::File::open(path).ok()?;
    let mut reader = std::io::BufReader::new(file);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "MODULE" {
        return None;
    }
    let _os = parts.next()?;
    let _arch = parts.next()?;
    let debug_id = parts.next()?.to_string();
    let name = parts.next().unwrap_or("").to_string();
    // INFO CODE_ID 行在文件头部(MODULE 之后、首个 FUNC/STACK 之前)。
    let mut code_id = None;
    for _ in 0..64 {
        line.clear();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        if let Some(rest) = line.trim_start().strip_prefix("INFO CODE_ID ") {
            code_id = rest.split_whitespace().next().map(str::to_string);
            break;
        }
        if line.starts_with("FUNC ") || line.starts_with("STACK ") || line.starts_with("PUBLIC ") {
            break;
        }
    }
    Some(LocalSym {
        path: path.to_path_buf(),
        debug_id,
        code_id,
        name,
    })
}

/// 网络与缓存限制。
#[derive(Debug, Clone)]
pub struct Limits {
    pub timeout: Duration,
    /// 单次下载大小上限。
    pub max_download_bytes: u64,
    /// 最大并发下载数。
    pub max_concurrent: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            max_download_bytes: 512 * 1024 * 1024,
            max_concurrent: 4,
        }
    }
}

/// 查找配置。
#[derive(Debug, Clone, Default)]
pub struct ResolverConfig {
    pub symbol_paths: Vec<PathBuf>,
    /// 用户显式指定的主程序(`--binary`),按文件名辅助匹配。
    pub user_binary: Option<PathBuf>,
    /// 用户显式指定的独立调试文件(`--debug-file`)。
    pub user_debug_file: Option<PathBuf>,
    pub debuginfod_urls: Vec<String>,
    pub cache_dir: PathBuf,
    pub limits: Limits,
}

/// 单个模块的产物与符号状态汇总。
#[derive(Debug, Clone, Default)]
pub struct ModuleArtifacts {
    pub executable: Option<ArtifactStatus>,
    pub debuginfo: Option<ArtifactStatus>,
    pub symbols: Option<SymbolStatus>,
    /// 匹配产物核验出的完整 Build ID(dump 截短时补全)。
    pub resolved_build_id: Option<String>,
}

/// 成功解析到的产物。
#[derive(Debug, Clone)]
pub struct ResolvedArtifact {
    pub path: PathBuf,
    pub origin: ArtifactOrigin,
    pub build_id: String,
    pub has_debug_info: bool,
}

/// (模块键, 产物类型) → 闩锁表。
type LatchMap = HashMap<(String, ArtifactKind), Arc<AsyncMutex<()>>>;

/// 产物解析器:串起用户文件、本地索引、缓存与 debuginfod。
pub struct ArtifactResolver {
    cfg: ResolverConfig,
    local: LocalIndex,
    client: DebuginfodClient,
    states: Mutex<HashMap<String, ModuleArtifacts>>,
    /// (模块键, 产物类型) → 闩锁,合并并发请求。
    latches: Mutex<LatchMap>,
    semaphore: Arc<Semaphore>,
}

impl ArtifactResolver {
    pub fn new(cfg: ResolverConfig) -> Self {
        let local = LocalIndex::scan(&cfg.symbol_paths);
        let client = DebuginfodClient::new(cfg.limits.timeout, cfg.limits.max_download_bytes);
        let semaphore = Arc::new(Semaphore::new(cfg.limits.max_concurrent.max(1)));
        Self {
            cfg,
            local,
            client,
            states: Mutex::new(HashMap::new()),
            latches: Mutex::new(HashMap::new()),
            semaphore,
        }
    }

    /// 解析指定产物。并发调用按 (模块, 类型) 合并;结果写入状态表。
    pub async fn resolve(
        &self,
        kind: ArtifactKind,
        ident: &ModuleIdentity,
    ) -> Result<ResolvedArtifact, ArtifactStatus> {
        let key = ident.key();

        // 同键请求合并:拿闩锁后复查状态表。
        let latch = {
            let mut map = self.latches.lock().unwrap();
            map.entry((key.clone(), kind))
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        let _guard = latch.lock().await;

        let result = self.resolve_uncached(kind, ident).await;
        match &result {
            Ok(artifact) => {
                let mut states = self.states.lock().unwrap();
                let entry = states.entry(key).or_default();
                entry.set_status(
                    kind,
                    ArtifactStatus::Ok {
                        origin: artifact.origin.clone(),
                        build_id: artifact.build_id.clone(),
                        has_debug_info: artifact.has_debug_info,
                    },
                );
                if entry.resolved_build_id.is_none() {
                    entry.resolved_build_id = Some(artifact.build_id.clone());
                }
            }
            Err(status) => {
                // 保留更具体的失败原因;避免用 NoSource 覆盖 IdentityMismatch 等。
                let mut states = self.states.lock().unwrap();
                let entry = states.entry(key).or_default();
                let replace = match entry.status(kind) {
                    None => true,
                    Some(ArtifactStatus::NoSource) => true,
                    Some(_) => false,
                };
                if replace {
                    entry.set_status(kind, status.clone());
                }
            }
        }
        result
    }

    /// 只做本地与缓存检查,不发起网络请求;用于报告收尾。
    pub fn probe_local(
        &self,
        kind: ArtifactKind,
        ident: &ModuleIdentity,
    ) -> Result<ResolvedArtifact, ArtifactStatus> {
        self.local_and_cache(kind, ident)
    }

    async fn resolve_uncached(
        &self,
        kind: ArtifactKind,
        ident: &ModuleIdentity,
    ) -> Result<ResolvedArtifact, ArtifactStatus> {
        // 本地(用户指定 + 扫描)与缓存。身份不匹配只否定对应的单个候选
        // (例如用户指定的主程序对 `.so` 模块必然不匹配),不得据此阻断
        // 对同一模块的其他来源(缓存、debuginfod)的查找。
        let local = self.local_and_cache(kind, ident);

        // 本地命中的调试文件不含 DWARF(例如符号目录里只有剥离后的
        // 发布镜像)时,它对 `DebugInfo` 的价值有限:保留为回退,继续向
        // debuginfod 请求真正的独立 `.debug`。本地镜像仍用于展开。
        let stripped_debug_fallback = match &local {
            Ok(a)
                if kind == ArtifactKind::DebugInfo
                    && !a.has_debug_info
                    && ident.full_build_id().is_some()
                    && !self.cfg.debuginfod_urls.is_empty()
                    && matches!(
                        a.origin,
                        ArtifactOrigin::UserSpecified { .. } | ArtifactOrigin::SymbolPath { .. }
                    ) =>
            {
                Some(a.clone())
            }
            _ => None,
        };

        let local_mismatch = match local {
            Ok(a) => {
                if stripped_debug_fallback.is_some() {
                    // 继续尝试网络,失败时回退到本地剥离产物。
                } else {
                    return Ok(a);
                }
                None
            }
            Err(status) => {
                if matches!(status, ArtifactStatus::IdentityMismatch { .. }) {
                    Some(status)
                } else {
                    None
                }
            }
        };

        match self.fetch_remote(kind, ident).await {
            Ok(a) => Ok(a),
            Err(remote) => {
                // 远程没有更好的调试文件:回退到本地剥离产物(仍可用于展开)。
                if let Some(fallback) = stripped_debug_fallback {
                    return Ok(fallback);
                }
                // 网络也未取得时,保留本地身份不匹配的诊断价值。
                match local_mismatch {
                    Some(m)
                        if matches!(
                            remote,
                            ArtifactStatus::NoSource | ArtifactStatus::NotArchived { .. }
                        ) =>
                    {
                        Err(m)
                    }
                    _ => Err(remote),
                }
            }
        }
    }

    fn local_and_cache(
        &self,
        kind: ArtifactKind,
        ident: &ModuleIdentity,
    ) -> Result<ResolvedArtifact, ArtifactStatus> {
        let mut mismatch: Option<ArtifactStatus> = None;

        // 1. 用户显式指定的文件。
        let user_path = match kind {
            ArtifactKind::Executable => self.cfg.user_binary.clone(),
            ArtifactKind::DebugInfo => self.cfg.user_debug_file.clone(),
        };
        if let Some(path) = user_path {
            let path_display = path.display().to_string();
            match probe_elf_file(&path) {
                Some(meta) => {
                    if match_identity(&meta, ident).is_some() {
                        return Ok(ResolvedArtifact {
                            path,
                            origin: ArtifactOrigin::UserSpecified { path: path_display },
                            build_id: meta.build_id.unwrap_or_default(),
                            has_debug_info: meta.has_debug_info,
                        });
                    }
                    // dump 无身份时,允许按文件名辅助匹配用户指定的主程序。
                    if ident.debug_id.is_none()
                        && ident.code_id.is_none()
                        && crate::util::basename(&path.to_string_lossy()) == ident.leaf
                        && let Some(build_id) = meta.build_id.clone()
                    {
                        return Ok(ResolvedArtifact {
                            path,
                            origin: ArtifactOrigin::UserSpecified { path: path_display },
                            build_id,
                            has_debug_info: meta.has_debug_info,
                        });
                    }
                    mismatch = Some(ArtifactStatus::IdentityMismatch {
                        path: path_display,
                        expected: ident.full_build_id().unwrap_or_else(|| "无".into()),
                        found: meta.build_id.unwrap_or_else(|| "无".into()),
                    });
                }
                None => {
                    mismatch = Some(ArtifactStatus::FetchFailed {
                        server: "用户指定文件".into(),
                        message: format!("无法解析 {path_display} (不是 ELF 或不可读)"),
                    });
                }
            }
        }

        // 2. 本地扫描索引。调试文件候选缺少 DWARF(剥离后的发布镜像)时
        // 先不返回:继续查缓存(可能有此前下载的真正 .debug),避免
        // 每次分析都重新下载。
        let mut stripped_local: Option<ResolvedArtifact> = None;
        if let Some(elf) = self.local.find_elf(ident, kind) {
            let artifact = ResolvedArtifact {
                path: elf.path.clone(),
                origin: ArtifactOrigin::SymbolPath {
                    path: elf.path.display().to_string(),
                },
                build_id: elf.meta.build_id.clone().unwrap_or_default(),
                has_debug_info: elf.meta.has_debug_info,
            };
            if kind == ArtifactKind::DebugInfo && !artifact.has_debug_info {
                stripped_local = Some(artifact);
            } else {
                return Ok(artifact);
            }
        }

        // 3. 缓存(此前从 debuginfod 下载)。
        if let Some(build_id) = ident.full_build_id() {
            for server in &self.cfg.debuginfod_urls {
                let path = self.cache_path(server, &build_id, kind);
                let path_display = path.display().to_string();
                if path.is_file()
                    && let Some(meta) = probe_elf_file(&path)
                    && match_identity(&meta, ident).is_some()
                {
                    return Ok(ResolvedArtifact {
                        path,
                        origin: ArtifactOrigin::Cache { path: path_display },
                        build_id: meta.build_id.unwrap_or_default(),
                        has_debug_info: meta.has_debug_info,
                    });
                }
            }
        }
        if let Some(stripped) = stripped_local {
            return Ok(stripped);
        }

        // 3.5 扫描目录中有同名文件但 Build ID 不符 → 报告身份不匹配。
        if mismatch.is_none()
            && let Some(conflict) = self.local.find_conflicting(ident)
        {
            mismatch = Some(ArtifactStatus::IdentityMismatch {
                path: conflict.path.display().to_string(),
                expected: ident.full_build_id().unwrap_or_else(|| "无".into()),
                found: conflict
                    .meta
                    .build_id
                    .clone()
                    .unwrap_or_else(|| "无".into()),
            });
        }
        if let Some(m) = mismatch {
            return Err(m);
        }
        if ident.debug_id.is_none() && ident.code_id.is_none() {
            return Err(ArtifactStatus::MissingIdentity);
        }
        if self.cfg.debuginfod_urls.is_empty() {
            return Err(ArtifactStatus::NoSource);
        }
        Err(ArtifactStatus::NoSource)
    }

    async fn fetch_remote(
        &self,
        kind: ArtifactKind,
        ident: &ModuleIdentity,
    ) -> Result<ResolvedArtifact, ArtifactStatus> {
        let Some(build_id) = ident.full_build_id() else {
            return Err(ArtifactStatus::MissingIdentity);
        };
        if self.cfg.debuginfod_urls.is_empty() {
            return Err(ArtifactStatus::NoSource);
        }

        let mut last_not_archived = None;
        let mut last_error = None;
        for server in self.cfg.debuginfod_urls.clone() {
            let permit = self.semaphore.clone().acquire_owned().await.unwrap();
            let client = self.client.clone();
            let bid = build_id.clone();
            let k = kind;
            let fetch_server = server.clone();
            let result = tokio::task::spawn_blocking(move || match k {
                ArtifactKind::Executable => client.fetch_executable(&fetch_server, &bid),
                ArtifactKind::DebugInfo => client.fetch_debuginfo(&fetch_server, &bid),
            })
            .await;
            drop(permit);

            let bytes = match result {
                Ok(FetchResult::Ok(bytes)) => bytes,
                Ok(FetchResult::NotFound) => {
                    last_not_archived = Some(server.clone());
                    continue;
                }
                Ok(FetchResult::Failed(message)) => {
                    last_error = Some(ArtifactStatus::FetchFailed {
                        server: server.clone(),
                        message,
                    });
                    continue;
                }
                Err(join) => {
                    last_error = Some(ArtifactStatus::FetchFailed {
                        server: server.clone(),
                        message: format!("下载任务失败:{join}"),
                    });
                    continue;
                }
            };

            // 核验下载产物的完整 Build ID,防止网关返回错误内容。
            let Some(meta) = probe_elf_bytes(&bytes) else {
                last_error = Some(ArtifactStatus::FetchFailed {
                    server: server.clone(),
                    message: "下载内容不是 ELF".into(),
                });
                continue;
            };
            if meta.build_id.as_deref() != Some(build_id.as_str()) {
                last_error = Some(ArtifactStatus::IdentityMismatch {
                    path: format!("{server} (下载)"),
                    expected: build_id.clone(),
                    found: meta.build_id.unwrap_or_else(|| "无".into()),
                });
                continue;
            }

            // 写入缓存后返回。
            let cache_path = self.cache_path(&server, &build_id, kind);
            if write_atomic(&cache_path, &bytes).is_err() {
                last_error = Some(ArtifactStatus::FetchFailed {
                    server: server.clone(),
                    message: format!("写入缓存失败:{}", cache_path.display()),
                });
                continue;
            }
            return Ok(ResolvedArtifact {
                path: cache_path.clone(),
                origin: ArtifactOrigin::Debuginfod {
                    server: server.clone(),
                    path: cache_path.display().to_string(),
                },
                build_id,
                has_debug_info: meta.has_debug_info,
            });
        }

        if let Some(e) = last_error {
            return Err(e);
        }
        if let Some(server) = last_not_archived {
            return Err(ArtifactStatus::NotArchived { server });
        }
        Err(ArtifactStatus::NoSource)
    }

    fn cache_path(&self, server: &str, build_id: &str, kind: ArtifactKind) -> PathBuf {
        self.cfg
            .cache_dir
            .join("debuginfod")
            .join(debuginfod::server_dir_name(server))
            .join(build_id)
            .join(kind.cache_leaf())
    }

    /// 源码缓存路径。
    pub fn source_cache_path(&self, server: &str, build_id: &str, source_path: &str) -> PathBuf {
        self.cfg
            .cache_dir
            .join("source")
            .join(debuginfod::server_dir_name(server))
            .join(build_id)
            .join(format!("{}.txt", crate::util::path_hash(source_path)))
    }

    pub fn config(&self) -> &ResolverConfig {
        &self.cfg
    }

    /// 暴露 `.sym` 索引(symbols 模块使用)。
    pub fn local_sym_index(&self) -> &LocalIndex {
        &self.local
    }

    pub fn client(&self) -> &DebuginfodClient {
        &self.client
    }

    pub fn semaphore(&self) -> &Arc<Semaphore> {
        &self.semaphore
    }

    /// 记录/读取符号状态。
    pub fn record_symbols(&self, key: &str, status: SymbolStatus) {
        self.states
            .lock()
            .unwrap()
            .entry(key.to_string())
            .or_default()
            .symbols = Some(status);
    }

    /// 读取模块状态;不存在时用 `probe_local` 填充(不联网)。
    pub fn finalize_module(&self, ident: &ModuleIdentity) -> ModuleArtifacts {
        let key = ident.key();
        let mut entry = {
            let states = self.states.lock().unwrap();
            states.get(&key).cloned().unwrap_or_default()
        };
        if entry.executable.is_none() {
            entry.executable = Some(match self.probe_local(ArtifactKind::Executable, ident) {
                Ok(a) => ArtifactStatus::Ok {
                    origin: a.origin,
                    build_id: a.build_id,
                    has_debug_info: a.has_debug_info,
                },
                Err(e) => e,
            });
            if entry.resolved_build_id.is_none()
                && let Some(a) = entry.executable.as_ref()
                && let ArtifactStatus::Ok { build_id, .. } = a
            {
                entry.resolved_build_id = Some(build_id.clone());
            }
        }
        if entry.debuginfo.is_none() {
            entry.debuginfo = Some(match self.probe_local(ArtifactKind::DebugInfo, ident) {
                Ok(a) => ArtifactStatus::Ok {
                    origin: a.origin,
                    build_id: a.build_id,
                    has_debug_info: a.has_debug_info,
                },
                Err(e) => e,
            });
        }
        entry
    }
}

impl ModuleArtifacts {
    fn status(&self, kind: ArtifactKind) -> Option<&ArtifactStatus> {
        match kind {
            ArtifactKind::Executable => self.executable.as_ref(),
            ArtifactKind::DebugInfo => self.debuginfo.as_ref(),
        }
    }

    fn set_status(&mut self, kind: ArtifactKind, status: ArtifactStatus) {
        match kind {
            ArtifactKind::Executable => self.executable = Some(status),
            ArtifactKind::DebugInfo => self.debuginfo = Some(status),
        }
    }
}

/// 原子写:先写临时文件再 rename。
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(build_id: Option<&str>, guid: Option<&str>) -> ModuleIdentity {
        ModuleIdentity {
            debug_id: guid.map(|g| g.parse().unwrap()),
            code_id: build_id.map(|b| CodeId::new(b.to_string())),
            leaf: "libtest.so".into(),
        }
    }

    #[test]
    fn guid_matches_uses_first_16_bytes() {
        // build id = 20 字节;GUID 只取前 16 字节。
        let build_id = "00112233445566778899aabbccddeeff0011";
        let bytes = hex_to_bytes(build_id).unwrap();
        let debug = debugid::DebugId::from_guid_age(&bytes[..16], 0).unwrap();
        assert!(guid_matches(build_id, &debug));
        // 最后 4 字节不同的 build id 仍匹配同一 GUID。
        assert!(guid_matches("00112233445566778899aabbccddeeffffff", &debug));
        // 前 16 字节不同则不匹配。
        assert!(!guid_matches(
            "ff112233445566778899aabbccddeeff0011",
            &debug
        ));
    }

    #[test]
    fn match_identity_full_vs_truncated() {
        let meta = ElfMeta {
            build_id: Some("aabbccddeeff00112233445566778899aabb".into()),
            has_debug_info: true,
            has_exec_segments: true,
        };
        // 1. 完整 ID 相等 → Full。
        let full = ident(Some("aabbccddeeff00112233445566778899aabb"), None);
        assert_eq!(match_identity(&meta, &full), Some(IdMatch::Full));

        // 2. dump 带完整 ID 但前 16 字节相同、末尾不同 → 拒绝,
        //    不得回退到 GUID 前缀匹配(那是另一个构建)。
        let prefix_same_tail_diff = ident(Some("aabbccddeeff00112233445566778899ffff"), None);
        assert_eq!(
            match_identity(&meta, &prefix_same_tail_diff),
            None,
            "完整 ID 尾部不同必须拒绝"
        );

        // 3. dump 只带旧标识(Breakpad GUID,无完整 ID)→ 前缀回退。
        let bytes = hex_to_bytes("aabbccddeeff00112233445566778899aabb").unwrap();
        let debug = debugid::DebugId::from_guid_age(&bytes[..16], 0).unwrap();
        let truncated = ModuleIdentity {
            debug_id: Some(debug),
            code_id: None,
            leaf: "x".into(),
        };
        assert_eq!(
            match_identity(&meta, &truncated),
            Some(IdMatch::TruncatedGuid)
        );

        let wrong = ident(Some("111111111111111111111111111111111111"), None);
        assert_eq!(match_identity(&meta, &wrong), None);
    }

    #[test]
    fn sym_file_probe() {
        let dir = std::env::temp_dir().join(format!("zmtest-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let sym = dir.join("test.sym");
        fs::write(
            &sym,
            "MODULE Linux x86_64 4F2A1B0C3D4E5F60718293A4B5C6D7E80 libtest.so\n\
             INFO CODE_ID aa112233445566778899aabbccddeeff0011 libtest.so\n",
        )
        .unwrap();
        let probed = probe_sym_file(&sym).unwrap();
        assert_eq!(probed.name, "libtest.so");
        assert_eq!(probed.debug_id.len(), 33); // 32 hex + age
        assert_eq!(
            probed.code_id.as_deref(),
            Some("aa112233445566778899aabbccddeeff0011")
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn find_sym_matches_breakpad_module_id() {
        // MODULE 行使用 Breakpad 格式(无连字符大写 GUID + Age);
        // 用普通 DebugId 显示格式(带连字符 UUID)查找不得命中。
        let dir = std::env::temp_dir().join(format!("zmsym-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let bytes = hex_to_bytes("4f2a1b0c3d4e5f60718293a4b5c6d7e8").unwrap();
        let debug = debugid::DebugId::from_guid_age(&bytes, 0).unwrap();
        fs::write(
            dir.join("libtest.sym"),
            format!("MODULE Linux x86_64 {} libtest.so\n", debug.breakpad()),
        )
        .unwrap();
        let index = LocalIndex::scan(std::slice::from_ref(&dir));

        let mut ident = ident(None, None);
        ident.debug_id = Some(debug);
        let found = index.find_sym(&ident).expect("应按 Breakpad 格式命中 .sym");
        assert_eq!(found.name, "libtest.so");

        // 大小写不敏感:小写的 MODULE ID 同样命中。
        fs::write(
            dir.join("lower.sym"),
            format!(
                "MODULE Linux x86_64 {} libtest.so\n",
                debug.breakpad().to_string().to_lowercase()
            ),
        )
        .unwrap();
        let index = LocalIndex::scan(std::slice::from_ref(&dir));
        assert!(index.find_sym(&ident).is_some());

        // 不同 GUID 不命中。
        let other_bytes = hex_to_bytes("00112233445566778899aabbccddeeff").unwrap();
        ident.debug_id = Some(debugid::DebugId::from_guid_age(&other_bytes, 0).unwrap());
        assert!(index.find_sym(&ident).is_none());
        fs::remove_dir_all(&dir).ok();
    }

    /// 测试桩:实现 minidump 的 Module trait,可控身份标识。
    struct StubModule {
        debug_id: Option<DebugId>,
        code_id: Option<CodeId>,
    }

    impl minidump::Module for StubModule {
        fn base_address(&self) -> u64 {
            0x1000
        }
        fn size(&self) -> u64 {
            1
        }
        fn code_file(&self) -> std::borrow::Cow<'_, str> {
            "/lib/libtest.so".into()
        }
        fn code_identifier(&self) -> Option<CodeId> {
            self.code_id.clone()
        }
        fn debug_file(&self) -> Option<std::borrow::Cow<'_, str>> {
            None
        }
        fn debug_identifier(&self) -> Option<DebugId> {
            self.debug_id
        }
        fn version(&self) -> Option<std::borrow::Cow<'_, str>> {
            None
        }
    }

    /// R2-P1:按 CodeView 记录类型区分完整 GNU Build ID 与旧 Breakpad
    /// PDB70 记录(后者的 code_identifier 是时间戳+大小,不是 Build ID)。
    #[test]
    fn from_module_with_cv_distinguishes_build_id_sources() {
        let build_id = "aa112233445566778899aabbccddeeff0011";
        let bytes = hex_to_bytes(build_id).unwrap();
        let debug = debugid::DebugId::from_guid_age(&bytes[..16], 0).unwrap();

        // 现代 ELF 记录:code_identifier 即完整 Build ID。
        let elf_module = StubModule {
            debug_id: Some(debug),
            code_id: Some(CodeId::new(build_id.into())),
        };
        let cv_elf = minidump::CodeView::Elf(minidump::format::CV_INFO_ELF {
            cv_signature: 0,
            build_id: bytes.clone(),
        });
        let modern = ModuleIdentity::from_module_with_cv(&elf_module, Some(&cv_elf));
        assert_eq!(modern.full_build_id().as_deref(), Some(build_id));
        let meta = ElfMeta {
            build_id: Some(build_id.into()),
            has_debug_info: true,
            has_exec_segments: true,
        };
        assert_eq!(match_identity(&meta, &modern), Some(IdMatch::Full));

        // 旧 PDB70 记录:GUID 相同,code_identifier 是时间戳+大小 →
        // 不得当作完整 Build ID,按截短 GUID 回退匹配同一产物。
        let pdb_module = StubModule {
            debug_id: Some(debug),
            code_id: Some(CodeId::new("DEADBEEF1a2b3c".into())),
        };
        let cv_pdb = minidump::CodeView::Pdb70(minidump::format::CV_INFO_PDB70 {
            cv_signature: 0x5344_5352,
            signature: minidump::format::GUID {
                data1: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
                data2: u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
                data3: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
                data4: bytes[8..16].try_into().unwrap(),
            },
            age: 0,
            pdb_file_name: vec![0],
        });
        let legacy = ModuleIdentity::from_module_with_cv(&pdb_module, Some(&cv_pdb));
        assert_eq!(
            legacy.full_build_id(),
            None,
            "PDB70 的时间戳+大小不是 Build ID"
        );
        assert_eq!(
            match_identity(&meta, &legacy),
            Some(IdMatch::TruncatedGuid),
            "历史 PDB70 记录应按 GUID 前缀匹配同一 .debug"
        );

        // 无 CodeView 记录:保留 trait 的原始值(CodeId 规整为小写)。
        let no_cv = ModuleIdentity::from_module_with_cv(&pdb_module, None);
        assert_eq!(
            no_cv.code_id.map(|c| c.as_str().to_string()),
            Some("deadbeef1a2b3c".into())
        );
    }

    /// R2-P2:dump 与 .sym 都带完整身份时核对 `INFO CODE_ID`;
    /// 截短 GUID 相同但完整身份不同的是另一个构建,必须跳过。
    #[test]
    fn sym_code_id_is_verified_when_available() {
        let dir = std::env::temp_dir().join(format!("zmsymcid-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let bytes = hex_to_bytes("4f2a1b0c3d4e5f60718293a4b5c6d7e8").unwrap();
        let debug = debugid::DebugId::from_guid_age(&bytes, 0).unwrap();
        let module_line = format!("MODULE Linux x86_64 {} libtest.so", debug.breakpad());

        // 两个 .sym:同一 MODULE 截短 ID,不同完整 CODE_ID。
        fs::write(
            dir.join("a.sym"),
            format!("{module_line}\nINFO CODE_ID aa112233445566778899aabbccddeeff0011\n"),
        )
        .unwrap();
        fs::write(
            dir.join("b.sym"),
            format!("{module_line}\nINFO CODE_ID bb112233445566778899aabbccddeeff0022\n"),
        )
        .unwrap();
        let index = LocalIndex::scan(std::slice::from_ref(&dir));

        // dump 完整 ID 匹配 a → 命中 a;匹配 b → 命中 b。
        let want = |id: &str| {
            let mut i = ident(Some(id), None);
            i.debug_id = Some(debug);
            i
        };
        assert!(
            index
                .find_sym(&want("aa112233445566778899aabbccddeeff0011"))
                .expect("完整 ID 一致应命中")
                .path
                .ends_with("a.sym")
        );
        assert!(
            index
                .find_sym(&want("bb112233445566778899aabbccddeeff0022"))
                .expect("完整 ID 一致应命中")
                .path
                .ends_with("b.sym")
        );

        // dump 完整 ID 不匹配任何候选 → 全部跳过(不用其他构建的符号)。
        assert!(
            index
                .find_sym(&want("cc112233445566778899aabbccddeeff0033"))
                .is_none(),
            "CODE_ID 不符的 .sym 必须跳过"
        );

        // 历史 .sym(无 INFO CODE_ID)保持兼容。
        fs::remove_file(dir.join("a.sym")).unwrap();
        fs::remove_file(dir.join("b.sym")).unwrap();
        fs::write(dir.join("legacy.sym"), format!("{module_line}\n")).unwrap();
        let index = LocalIndex::scan(std::slice::from_ref(&dir));
        assert!(
            index
                .find_sym(&want("aa112233445566778899aabbccddeeff0011"))
                .is_some(),
            "无 INFO CODE_ID 的历史 .sym 应兼容命中"
        );
        fs::remove_dir_all(&dir).ok();
    }
}
