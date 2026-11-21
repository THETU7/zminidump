//! 通用工具函数。

/// 取路径的最后一段文件名(支持 Windows 分隔符)。
pub fn basename(path: &str) -> String {
    let p = path.trim_end_matches(['/', '\\']);
    match p.rsplit_once(['/', '\\']) {
        Some((_, leaf)) => leaf.to_string(),
        None => p.to_string(),
    }
}

/// 源码路径的稳定哈希(FNV-1a 64),用作缓存文件名。
pub fn path_hash(path: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in path.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

/// HTML 文本转义。
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_handles_unix_windows_and_bare() {
        assert_eq!(basename("/usr/lib/libtest.so"), "libtest.so");
        assert_eq!(basename("C:\\dir\\x.pdb"), "x.pdb");
        assert_eq!(basename("x.pdb"), "x.pdb");
        assert_eq!(basename(""), "");
    }

    #[test]
    fn path_hash_is_stable_and_distinct() {
        assert_eq!(path_hash("/a/b.c"), path_hash("/a/b.c"));
        assert_ne!(path_hash("/a/b.c"), path_hash("/a/b.d"));
    }

    #[test]
    fn escape_html_covers_special_chars() {
        assert_eq!(escape_html("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&#39;");
        assert_eq!(escape_html("安全路径"), "安全路径");
    }
}
