use crate::util::{basename, escape_html};
use std::fmt::Write as _;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Language {
    CFamily,
    Rust,
}

impl Language {
    fn for_path(path: &str) -> Option<Self> {
        let name = basename(path);
        match name.rsplit_once('.')?.1.to_ascii_lowercase().as_str() {
            "c" | "h" | "cc" | "cp" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" | "inl" => {
                Some(Self::CFamily)
            }
            "rs" => Some(Self::Rust),
            _ => None,
        }
    }

    #[rustfmt::skip]
    fn is_keyword(self, word: &str) -> bool {
        match self {
            Self::CFamily => matches!(word,
                "alignas" | "alignof" | "asm" | "auto" | "bool" | "break" | "case" | "catch"
                    | "char" | "class" | "co_await" | "co_return" | "co_yield" | "concept"
                    | "const" | "const_cast" | "consteval" | "constexpr" | "constinit"
                    | "continue" | "decltype" | "default" | "delete" | "do" | "double"
                    | "dynamic_cast" | "else" | "enum" | "explicit" | "extern" | "false"
                    | "float" | "for" | "friend" | "goto" | "if" | "inline" | "int" | "long"
                    | "namespace" | "new" | "noexcept" | "nullptr" | "operator" | "private"
                    | "protected" | "public" | "register" | "reinterpret_cast" | "requires"
                    | "return" | "short" | "signed" | "sizeof" | "static" | "static_assert"
                    | "static_cast" | "struct" | "switch" | "template" | "this" | "thread_local"
                    | "throw" | "true" | "try" | "typedef" | "typename" | "union" | "unsigned"
                    | "using" | "virtual" | "void" | "volatile" | "wchar_t" | "while"
                    | "_Atomic" | "_Bool" | "_Generic" | "_Static_assert"
            ),
            Self::Rust => matches!(word,
                "as" | "async" | "await" | "bool" | "break" | "char" | "const" | "continue"
                    | "crate" | "dyn" | "else" | "enum" | "extern" | "f32" | "f64" | "false"
                    | "fn" | "for" | "i128" | "i16" | "i32" | "i64" | "i8" | "if" | "impl"
                    | "in" | "isize" | "let" | "loop" | "match" | "mod" | "move" | "mut" | "pub"
                    | "ref" | "return" | "self" | "Self" | "static" | "str" | "struct" | "super"
                    | "trait" | "true" | "type" | "u128" | "u16" | "u32" | "u64" | "u8"
                    | "unsafe" | "use" | "usize" | "where" | "while"
            ),
        }
    }
}

/// 按源码片段着色。跨越报告省略的行时，调用方会重置注释状态。
pub(super) struct Highlighter {
    language: Option<Language>,
    in_block_comment: bool,
}

impl Highlighter {
    pub(super) fn new(path: &str) -> Self {
        Self {
            language: Language::for_path(path),
            in_block_comment: false,
        }
    }

    pub(super) fn reset(&mut self) {
        self.in_block_comment = false;
    }

    pub(super) fn render_line(&mut self, html: &mut String, code: &str) {
        let Some(language) = self.language else {
            html.push_str(&escape_html(code));
            return;
        };

        let mut offset = 0;
        let mut plain_start = 0;
        while offset < code.len() {
            let (length, class) = self.token(&code[offset..], language);
            let end = offset + length;
            if let Some(class) = class {
                html.push_str(&escape_html(&code[plain_start..offset]));
                let _ = write!(
                    html,
                    "<span class=\"syntax-{class}\">{}</span>",
                    escape_html(&code[offset..end])
                );
                plain_start = end;
            }
            offset = end;
        }
        html.push_str(&escape_html(&code[plain_start..]));
    }

    fn token(&mut self, code: &str, language: Language) -> (usize, Option<&'static str>) {
        if self.in_block_comment || code.starts_with("/*") {
            let start = if self.in_block_comment { 0 } else { 2 };
            let end = code[start..].find("*/");
            self.in_block_comment = end.is_none();
            return (
                end.map_or(code.len(), |end| start + end + 2),
                Some("comment"),
            );
        }

        if code.starts_with("//") {
            return (code.len(), Some("comment"));
        }

        let first = code.chars().next().expect("token expects non-empty code");
        match first {
            '"' => (
                quoted_end(code, first).unwrap_or(code.len()),
                Some("string"),
            ),
            // Rust 的 'a 和 'label 是生命周期或标签，字符字面量只有一个字符或转义。
            '\'' if language == Language::CFamily || is_rust_character(code) => (
                quoted_end(code, first).unwrap_or(code.len()),
                Some("string"),
            ),
            '0'..='9' => (number_length(code, language), Some("number")),
            ch if ch.is_alphabetic() || ch == '_' => {
                let end = code
                    .find(|ch: char| !ch.is_alphanumeric() && ch != '_')
                    .unwrap_or(code.len());
                (end, language.is_keyword(&code[..end]).then_some("keyword"))
            }
            _ => (first.len_utf8(), None),
        }
    }
}

fn quoted_end(code: &str, quote: char) -> Option<usize> {
    let mut escaped = false;
    for (index, ch) in code.char_indices().skip(1) {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == quote {
            return Some(index + 1);
        }
    }
    None
}

fn is_rust_character(code: &str) -> bool {
    let body = &code[1..];
    body.starts_with('\\') || body.chars().nth(1) == Some('\'')
}

fn number_length(code: &str, language: Language) -> usize {
    let bytes = code.as_bytes();
    bytes
        .iter()
        .enumerate()
        .position(|(index, &byte)| match byte {
            b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'_' => false,
            b'.' => !bytes.get(index + 1).is_some_and(u8::is_ascii_digit),
            b'\'' if language == Language::CFamily => {
                !bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
            }
            _ => true,
        })
        .unwrap_or(bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highlights_cpp_literals_and_comments_with_escaped_content() {
        let mut highlighter = Highlighter::new(r"C:\source\example.CPP");
        let mut html = String::new();
        highlighter.render_line(&mut html, r#"static auto n = 0x2f; "// \"<tag>\"" /* 文"#);
        assert_eq!(
            html,
            concat!(
                r#"<span class="syntax-keyword">static</span> "#,
                r#"<span class="syntax-keyword">auto</span> n = <span class="syntax-number">0x2f</span>; "#,
                r#"<span class="syntax-string">&quot;// \&quot;&lt;tag&gt;\&quot;&quot;</span> "#,
                r#"<span class="syntax-comment">/* 文</span>"#,
            )
        );

        html.clear();
        highlighter.render_line(&mut html, "续 */ return 1'023; /*");
        assert_eq!(
            html,
            concat!(
                r#"<span class="syntax-comment">续 */</span> <span class="syntax-keyword">return</span> "#,
                r#"<span class="syntax-number">1&#39;023</span>; <span class="syntax-comment">/*</span>"#,
            )
        );

        highlighter.reset();
        html.clear();
        highlighter.render_line(&mut html, "if (x) // &");
        assert_eq!(
            html,
            r#"<span class="syntax-keyword">if</span> (x) <span class="syntax-comment">// &amp;</span>"#
        );
    }

    #[test]
    fn rust_lifetime_keeps_following_tokens_and_unknown_files_stay_plain() {
        let mut html = String::new();
        Highlighter::new("main.rs")
            .render_line(&mut html, "fn f<'a>(s: &'a str) { let c = '字'; }");
        assert!(html.contains("f&lt;&#39;a&gt;(s: &amp;&#39;a"));
        assert!(html.contains(r#"<span class="syntax-keyword">let</span>"#));
        assert!(html.contains(r#"<span class="syntax-string">&#39;字&#39;</span>"#));

        html.clear();
        Highlighter::new("plain.txt").render_line(&mut html, "if // <tag>");
        assert_eq!(html, "if // &lt;tag&gt;");
    }
}
