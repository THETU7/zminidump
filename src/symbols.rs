//! 符号供给:把产物解析结果接到 minidump-unwind 的 `SymbolProvider`。
//!
//! 优先使用 `--symbol-path` 中的预生成 Breakpad `.sym`(CI 产物);
//! 否则用 dump_syms 从核验过的 ELF(可执行文件 + 独立调试文件)现场
//! 生成 `.sym`,一次性提供函数名、文件行号、内联帧与 CFI 展开规则。
//! 独立调试文件不含 `.eh_frame`,CFI 需要可执行文件;两者都匹配时
//! 按 Build ID 合并生成。生成的符号缺展开规则(或本地完全没有产物)
//! 时,无论调试文件来自本地、缓存还是网络,都会尝试向 debuginfod
//! 获取可执行镜像补齐 CFI——即使缺少源码行号也能回溯。

use std::{path::PathBuf, sync::Arc};

use async_trait::async_trait;
use breakpad_symbols::{
    FileError, FileKind, LocateSymbolsResult, Module, SymbolError, SymbolFile, SymbolSupplier,
};
use dump_syms::{object_info::ObjectInfo, platform::Platform};

use crate::{
    artifacts::{ArtifactKind, ArtifactResolver, LocalSym, ModuleIdentity, ResolvedArtifact},
    report::SymbolStatus,
};

pub struct ArtifactSymbolSupplier {
    resolver: Arc<ArtifactResolver>,
}

impl ArtifactSymbolSupplier {
    pub fn new(resolver: Arc<ArtifactResolver>) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl SymbolSupplier for ArtifactSymbolSupplier {
    async fn locate_symbols(
        &self,
        module: &(dyn Module + Sync),
    ) -> Result<LocateSymbolsResult, SymbolError> {
        let ident = ModuleIdentity::from_module(module);
        let key = ident.key();

        // 1. 预生成 .sym(CI 产物)。
        if let Some(sym) = self.resolver.find_sym(&ident) {
            let path = sym.path.clone();
            let loaded = tokio::task::spawn_blocking(move || load_sym_file(&path)).await;
            match loaded {
                Ok(Ok(file)) => {
                    let detail = format!("预生成 .sym({})", sym.path.display());
                    let has_cfi = sym_file_has_cfi(&sym.path);
                    let has_lines = sym_file_has_lines(&sym.path);
                    self.resolver.record_symbols(
                        &key,
                        SymbolStatus::Loaded {
                            detail,
                            has_cfi,
                            has_lines,
                        },
                    );
                    return Ok(LocateSymbolsResult {
                        symbols: file,
                        extra_debug_info: None,
                    });
                }
                Ok(Err(message)) => {
                    self.resolver.record_symbols(
                        &key,
                        SymbolStatus::Corrupt {
                            detail: sym.path.display().to_string(),
                            message,
                        },
                    );
                    return Err(io_error(format!("损坏的 .sym:{}", sym.path.display())));
                }
                Err(e) => {
                    return Err(io_error(format!("读取 .sym 失败:{e}")));
                }
            }
        }

        // 2. 解析产物:调试文件(含网络),可执行文件先只查本地与缓存。
        let debug = self
            .resolver
            .resolve(ArtifactKind::DebugInfo, &ident)
            .await
            .ok();
        let exe = self
            .resolver
            .probe_local(ArtifactKind::Executable, &ident)
            .ok();

        let mut paths: Vec<PathBuf> = Vec::new();
        if let Some(a) = &exe {
            paths.push(a.path.clone());
        }
        if let Some(a) = &debug
            && !paths.contains(&a.path)
        {
            paths.push(a.path.clone());
        }

        // 3. 生成符号(CPU 密集,放阻塞线程)。
        let leaf = ident.leaf.clone();
        let gen_paths = paths.clone();
        let generated = tokio::task::spawn_blocking(move || generate_from_paths(&gen_paths, &leaf))
            .await
            .map_err(|e| io_error(format!("符号生成任务失败:{e}")));

        let first_result: Result<ObjectInfo, String> = match generated {
            Ok(inner) => inner,
            Err(e) => return Err(e),
        };
        let (mut merged, mut fail_reason) = match first_result {
            Ok(info) => (Some(info), None),
            Err(reason) => (None, Some(reason)),
        };

        // 4. 按缺失的展开信息决定是否查找可执行镜像:生成的符号缺 CFI
        //    (或完全没有可用产物)而本地没有可执行文件时,向 debuginfod
        //    请求 `/executable`——其 `.eh_frame` 可提供展开规则,即使没有
        //    行号也能回溯。无论调试文件来自本地、缓存还是网络。
        let lacks_unwind = merged
            .as_ref()
            .map(|m| !m.has_stack())
            .unwrap_or(true);
        if lacks_unwind
            && exe.is_none()
            && let Ok(net_exe) = self
                .resolver
                .resolve(ArtifactKind::Executable, &ident)
                .await
        {
            let mut retry = vec![net_exe.path.clone()];
            for p in &paths {
                if !retry.contains(p) {
                    retry.push(p.clone());
                }
            }
            let leaf = ident.leaf.clone();
            let retry_paths = retry.clone();
            let retry_result =
                tokio::task::spawn_blocking(move || generate_from_paths(&retry_paths, &leaf)).await;
            if let Ok(Ok(info)) = retry_result
                && (info.has_stack() || merged.is_none())
            {
                // 远程镜像补上了 CFI,或原本完全没有产物(即使无行号也优于缺失)。
                paths = retry;
                merged = Some(info);
                fail_reason = None;
            }
            // 否则保留首个结果:行号可能仍可用。
        }

        let Some(merged) = merged else {
            self.resolver.record_symbols(
                &key,
                SymbolStatus::Missing {
                    reason: fail_reason.unwrap_or_else(|| "没有可用产物".into()),
                },
            );
            return Err(SymbolError::NotFound);
        };

        let has_cfi = merged.has_stack();
        let mut text = Vec::with_capacity(1 << 20);
        if merged.dump(&mut text).is_err() {
            self.resolver.record_symbols(
                &key,
                SymbolStatus::Corrupt {
                    detail: paths
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                    message: "dump_syms 输出失败".into(),
                },
            );
            return Err(io_error("dump_syms 输出失败".into()));
        }
        let has_lines = text.windows(6).any(|w| w == b"\nFILE ");

        match SymbolFile::from_bytes(&text) {
            Ok(file) => {
                let detail = paths
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" + ");
                self.resolver.record_symbols(
                    &key,
                    SymbolStatus::Loaded {
                        detail: format!("由 ELF 生成({detail})"),
                        has_cfi,
                        has_lines,
                    },
                );
                Ok(LocateSymbolsResult {
                    symbols: file,
                    extra_debug_info: None,
                })
            }
            Err(e) => {
                self.resolver.record_symbols(
                    &key,
                    SymbolStatus::Corrupt {
                        detail: paths
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", "),
                        message: format!("{e}"),
                    },
                );
                Err(io_error(format!("{e}")))
            }
        }
    }

    async fn locate_file(
        &self,
        module: &(dyn Module + Sync),
        file_kind: FileKind,
    ) -> Result<PathBuf, FileError> {
        let ident = ModuleIdentity::from_module(module);
        let kind = match file_kind {
            FileKind::Binary => ArtifactKind::Executable,
            FileKind::ExtraDebugInfo | FileKind::BreakpadSym => ArtifactKind::DebugInfo,
        };
        self.resolver
            .resolve(kind, &ident)
            .await
            .map(|a| a.path)
            .map_err(|_| FileError::NotFound)
    }
}

fn load_sym_file(path: &PathBuf) -> Result<SymbolFile, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("读取失败:{e}"))?;
    SymbolFile::from_bytes(&bytes).map_err(|e| format!("{e}"))
}

fn sym_file_has_cfi(path: &std::path::Path) -> bool {
    std::fs::read(path)
        .map(|b| {
            let text = String::from_utf8_lossy(&b);
            text.lines()
                .any(|l| l.starts_with("STACK CFI") || l.starts_with("STACK WIN"))
        })
        .unwrap_or(false)
}

fn sym_file_has_lines(path: &std::path::Path) -> bool {
    std::fs::read(path)
        .map(|b| {
            let text = String::from_utf8_lossy(&b);
            text.lines().any(|l| l.starts_with("FILE "))
        })
        .unwrap_or(false)
}

/// 从多个同 Build ID 的 ELF 生成合并的 `ObjectInfo`。
fn generate_from_paths(paths: &[PathBuf], leaf: &str) -> Result<ObjectInfo, String> {
    let mut infos: Vec<ObjectInfo> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for path in paths {
        let buf = std::fs::read(path).map_err(|e| format!("读取 {} 失败:{e}", path.display()))?;
        match ObjectInfo::from_elf(&buf, leaf, Platform::Linux, None, true) {
            Ok(info) => infos.push(info),
            Err(e) => errors.push(format!("{}:{e}", path.display())),
        }
    }
    if infos.is_empty() {
        let mut reason = errors.join("; ");
        if reason.is_empty() {
            reason = "没有可用产物".into();
        }
        return Err(reason);
    }
    let mut iter = infos.into_iter();
    let mut acc = iter.next().expect("infos non-empty");
    for next in iter {
        acc = match ObjectInfo::merge(acc, next) {
            Ok(merged) => merged,
            Err(e) => {
                // 同一 Build ID 的产物合并失败极罕见;退回首个产物单独生成。
                eprintln!("zminidump: 符号合并失败:{e}");
                return generate_from_paths(&paths[..1], leaf);
            }
        };
    }
    Ok(acc)
}

fn io_error(message: String) -> SymbolError {
    SymbolError::LoadError(std::io::Error::other(message))
}

impl ArtifactResolver {
    /// 查找预生成 `.sym`(同步,只读索引)。
    pub fn find_sym(&self, ident: &ModuleIdentity) -> Option<LocalSym> {
        self.local_sym_index().find_sym(ident).cloned()
    }
}

#[allow(dead_code)]
fn _assert_send_sync() {
    fn check<T: Send + Sync>() {}
    check::<ResolvedArtifact>();
}
