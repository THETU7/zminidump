//! debuginfod 客户端:按 Build ID 获取 `executable`、`debuginfo` 与源码。
//!
//! 端点遵循 <https://sourceware.org/elfutils/Debuginfod.html>:
//! - `{base}/buildid/{id}/executable`
//! - `{base}/buildid/{id}/debuginfo`
//! - `{base}/source/{id}/{path}`(path 去掉开头的 `/`)
//!
//! 控制下载超时、单次下载大小;并发由调用方通过信号量控制。

use std::time::Duration;

use ureq::{Agent, Error};

/// 一次 debuginfod 请求的结果。
pub enum FetchResult {
    /// 200:返回内容。
    Ok(Vec<u8>),
    /// 404:服务器没有归档该产物。
    NotFound,
    /// 其他错误(网络、超时、5xx、超过大小上限等)。
    Failed(String),
}

/// HTTP client;`Agent` 内部为 Arc,克隆开销低。
#[derive(Clone)]
pub struct DebuginfodClient {
    agent: Agent,
    timeout: Duration,
    max_bytes: u64,
}

impl DebuginfodClient {
    pub fn new(timeout: Duration, max_bytes: u64) -> Self {
        let config = Agent::config_builder()
            .timeout_global(Some(timeout))
            .http_status_as_error(false) // 我们自行区分 404 与其他错误
            .max_redirects(10)
            .build();
        Self {
            agent: config.into(),
            timeout,
            max_bytes,
        }
    }

    /// 请求 `url`,限制读取的字节数。
    fn fetch(&self, url: &str) -> FetchResult {
        let response = match self.agent.get(url).call() {
            Ok(r) => r,
            Err(Error::StatusCode(code)) => {
                return if code == 404 {
                    FetchResult::NotFound
                } else {
                    FetchResult::Failed(format!("HTTP {code}"))
                };
            }
            Err(e) => return FetchResult::Failed(describe_error(e)),
        };

        let status = response.status().as_u16();
        if status == 404 {
            return FetchResult::NotFound;
        }
        if status != 200 {
            return FetchResult::Failed(format!("HTTP {status}"));
        }

        let mut body = Vec::new();
        // 带上限地读取,避免异常响应占满磁盘或内存。
        let mut limited = LimitedReader {
            inner: response.into_body().into_reader(),
            remaining: self.max_bytes,
        };
        match std::io::Read::read_to_end(&mut limited, &mut body) {
            Ok(_) => {
                if limited.remaining == 0 {
                    // 读满上限仍可能有剩余数据,视为超限。
                    return FetchResult::Failed(format!(
                        "下载超过大小上限 {} 字节",
                        self.max_bytes
                    ));
                }
                FetchResult::Ok(body)
            }
            Err(e) => FetchResult::Failed(format!("读取响应失败:{e}")),
        }
    }

    /// 获取模块的可执行文件。
    pub fn fetch_executable(&self, server: &str, build_id: &str) -> FetchResult {
        self.fetch(&format!("{server}/buildid/{build_id}/executable"))
    }

    /// 获取模块的独立调试文件。
    pub fn fetch_debuginfo(&self, server: &str, build_id: &str) -> FetchResult {
        self.fetch(&format!("{server}/buildid/{build_id}/debuginfo"))
    }

    /// 获取源码文件。`path` 为 DWARF 记录的路径,去掉开头的 `/`。
    pub fn fetch_source(&self, server: &str, build_id: &str, path: &str) -> FetchResult {
        let trimmed = path.trim_start_matches('/');
        self.fetch(&format!("{server}/source/{build_id}/{trimmed}"))
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// 到达上限后立即停止读取的 reader。
struct LimitedReader<R: std::io::Read> {
    inner: R,
    remaining: u64,
}

impl<R: std::io::Read> std::io::Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let max = buf.len().min(self.remaining as usize);
        let n = self.inner.read(&mut buf[..max])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

fn describe_error(e: Error) -> String {
    match e {
        Error::StatusCode(c) => format!("HTTP {c}"),
        Error::Timeout(_) => "请求超时".to_string(),
        Error::HostNotFound => "域名解析失败".to_string(),
        Error::BadUri(u) => format!("无效 URL:{u}"),
        Error::Io(e) => format!("网络 IO 错误:{e}"),
        other => other.to_string(),
    }
}

/// 将服务器 URL 规整为缓存目录名:去掉 scheme,保留 host[:port]/path 前缀。
pub fn server_dir_name(server: &str) -> String {
    let s = server
        .trim()
        .trim_end_matches('/')
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("server");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_dir_name_normalizes() {
        assert_eq!(
            server_dir_name("https://debuginfod.example.com/"),
            "debuginfod.example.com"
        );
        assert_eq!(server_dir_name("http://127.0.0.1:8002"), "127.0.0.1_8002");
        assert_eq!(server_dir_name("  "), "server");
    }
}
