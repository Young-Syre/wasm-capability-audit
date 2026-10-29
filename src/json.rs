//! A very small JSON writer.
//!
//! Hand-written, because the crate has no dependencies. The only part worth
//! care is string escaping, and it is tested directly: quotes, backslashes,
//! the named control escapes, every other character below 0x20 as `\u00XX`,
//! and non-ASCII passed through as UTF-8. WebAssembly names are arbitrary
//! UTF-8 and go straight into this output, so getting it wrong would produce
//! invalid JSON on exactly the modules most worth looking at.

/// Escape a string into a JSON string literal, including the surrounding
/// quotes.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A JSON array of strings.
pub fn string_array<I, S>(items: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let parts: Vec<String> = items.into_iter().map(|s| quote(s.as_ref())).collect();
    format!("[{}]", parts.join(","))
}

/// Builds one JSON object, field by field, in insertion order.
#[derive(Debug, Default)]
pub struct Obj {
    fields: Vec<String>,
}

impl Obj {
    /// An empty object.
    pub fn new() -> Self {
        Obj::default()
    }

    /// A string field.
    pub fn str_field(mut self, key: &str, value: &str) -> Self {
        self.fields.push(format!("{}:{}", quote(key), quote(value)));
        self
    }

    /// A field holding an already-rendered JSON value.
    pub fn raw(mut self, key: &str, value: impl Into<String>) -> Self {
        self.fields.push(format!("{}:{}", quote(key), value.into()));
        self
    }

    /// An unsigned-integer field.
    pub fn num(self, key: &str, value: u64) -> Self {
        self.raw(key, value.to_string())
    }

    /// A boolean field.
    pub fn bool_field(self, key: &str, value: bool) -> Self {
        self.raw(key, if value { "true" } else { "false" })
    }

    /// An optional unsigned-integer field, rendered as `null` when absent.
    pub fn opt_num(self, key: &str, value: Option<u64>) -> Self {
        match value {
            Some(v) => self.num(key, v),
            None => self.raw(key, "null"),
        }
    }

    /// Render the object.
    pub fn finish(self) -> String {
        format!("{{{}}}", self.fields.join(","))
    }
}
