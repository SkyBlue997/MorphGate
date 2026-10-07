//! The Web SDK directory (`[sdk] dir`, docs/impl/phase1-spec.md §11.1,
//! §11.2, §10.4, ruling I-28).
//!
//! Loaded once at start-up (and by `--check-config`): `manifest.json` is
//! parsed strictly, every listed file is read into memory and checked against
//! its SHA-256, and the challenge page template is checked against the §11.2
//! contract with [`validate_template`], a rule-for-rule port of
//! `sdk/web/scripts/build-dist.mjs` `validateTemplate` (I-28). The files in
//! `files` are served under `/__mg/s/<name>` from memory
//! ([`crate::mg_endpoints`]); `challenge.html` is pre-split into literal text
//! and placeholders ([`Template`]) and rendered per response
//! ([`crate::pages`]).
//!
//! # Porting notes
//!
//! `validateTemplate` is written with JavaScript regular expressions. The
//! scanners below reproduce their matching exactly, on byte offsets instead
//! of UTF-16 offsets (every delimiter involved is ASCII, so the two agree):
//!
//! * tags `/<([A-Za-z][A-Za-z0-9-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>/g`: a
//!   quote opens a quoted run that must close, and an unterminated quote
//!   means no tag starts at that `<` (`scan_tags`);
//! * attributes ``/([^\s"'=<>/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g``
//!   with ECMAScript `\s` ([`is_js_space`]);
//! * placeholders `/\{\{([^{}]*)\}\}/g` ([`placeholder_spans`]);
//! * comments `/<!--[\s\S]*?(?:-->|$)/g` and `<script>` / `<style>` raw text
//!   `/(<(script|style)\b(?:…)*>)([\s\S]*?)(?:<\/\2\s*>|$)/gi`, the regions
//!   where no placeholder may appear.
//!
//! The template is at most 32 KiB, every scanner is at worst quadratic in
//! it, and none panics (tested with 10,000 mutated templates).

use bytes::Bytes;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;

/// The manifest file name.
pub const MANIFEST: &str = "manifest.json";
/// The only template of Phase 1.
pub const TEMPLATE: &str = "challenge.html";
/// Template size limit (§11.2).
pub const MAX_TEMPLATE_BYTES: usize = 32 * 1024;
/// Size limit of one served SDK file (the gzip budget is 30 KiB; this only
/// bounds memory).
pub const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// Exactly these placeholders, each at least once (§11.2).
pub const PLACEHOLDERS: [&str; 10] = [
    "lang",
    "nonce",
    "sdk_src",
    "prefix",
    "c",
    "type",
    "pow_bits",
    "ret",
    "request_id",
    "state",
];

/// A placeholder of [`PLACEHOLDERS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placeholder {
    Lang,
    Nonce,
    SdkSrc,
    Prefix,
    C,
    Type,
    PowBits,
    Ret,
    RequestId,
    State,
}

impl Placeholder {
    const ALL: [Self; 10] = [
        Self::Lang,
        Self::Nonce,
        Self::SdkSrc,
        Self::Prefix,
        Self::C,
        Self::Type,
        Self::PowBits,
        Self::Ret,
        Self::RequestId,
        Self::State,
    ];

    fn from_name(name: &str) -> Option<Self> {
        PLACEHOLDERS
            .iter()
            .position(|p| *p == name)
            .map(|i| Self::ALL[i])
    }
}

/// One piece of the pre-split template.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Text(String),
    Value(Placeholder),
}

/// `challenge.html`, split at its placeholders. Only built from a template
/// that passed [`validate_template`].
#[derive(Clone, PartialEq, Eq)]
pub struct Template {
    segments: Vec<Segment>,
    /// Bytes of the literal text (a lower bound of the rendered size).
    text_len: usize,
}

impl fmt::Debug for Template {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Template")
            .field("segments", &self.segments.len())
            .field("text_len", &self.text_len)
            .finish()
    }
}

impl Template {
    /// Splits a validated template at every placeholder match (the same
    /// scanner as the validator, so a validated template has only known
    /// names).
    fn split(html: &str) -> Result<Self, String> {
        let mut segments = Vec::new();
        let mut at = 0;
        let mut text_len = 0;
        for (start, end) in placeholder_spans(html) {
            if start > at {
                segments.push(Segment::Text(html[at..start].to_owned()));
                text_len += start - at;
            }
            let name = &html[start + 2..end - 2];
            let p = Placeholder::from_name(name)
                .ok_or_else(|| format!("unknown placeholder {{{{{name}}}}}"))?;
            segments.push(Segment::Value(p));
            at = end;
        }
        if at < html.len() {
            segments.push(Segment::Text(html[at..].to_owned()));
            text_len += html.len() - at;
        }
        Ok(Self { segments, text_len })
    }

    /// Renders the page: every placeholder becomes `value(p)` escaped for an
    /// HTML attribute (`&` `<` `>` `"` `'`, §11.2), then substituted as
    /// plain text. The placeholder-context rule of [`validate_template`]
    /// (I-28) makes that escaping sufficient wherever a placeholder appears.
    pub fn render<'a>(&self, value: impl Fn(Placeholder) -> &'a str) -> String {
        let mut out = String::with_capacity(self.text_len + 1024);
        for s in &self.segments {
            match s {
                Segment::Text(t) => out.push_str(t),
                Segment::Value(p) => escape_html_into(value(*p), &mut out),
            }
        }
        out
    }
}

/// HTML attribute escaping of §11.2: `&` `<` `>` `"` `'`.
pub fn escape_html_into(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
}

/// A loaded, verified SDK directory.
#[derive(Clone)]
pub struct SdkDir {
    /// `manifest.build` (16 lower-case hex characters).
    pub build: String,
    /// The SDK file name (`mg.<hex16>.js`).
    pub sdk: String,
    /// Served files by name (`/__mg/s/<name>`).
    pub files: BTreeMap<String, Bytes>,
    /// `challenge.html`, pre-split.
    pub template: Arc<Template>,
}

impl fmt::Debug for SdkDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdkDir")
            .field("build", &self.build)
            .field("sdk", &self.sdk)
            .field("files", &self.files.keys().collect::<Vec<_>>())
            .field("template", &self.template)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    v: u32,
    build: String,
    sdk: String,
    files: BTreeMap<String, String>,
    templates: BTreeMap<String, String>,
}

impl SdkDir {
    /// Loads and verifies `dir`. The error names the first problem.
    pub fn load(dir: &Path) -> Result<Self, String> {
        let manifest_path = dir.join(MANIFEST);
        let raw = read_capped(&manifest_path, MAX_MANIFEST_BYTES)?;
        if raw.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
            return Err(format!("{}: not a JSON object", manifest_path.display()));
        }
        let m: Manifest = serde_json::from_slice(&raw)
            .map_err(|e| format!("{}: {e}", manifest_path.display()))?;
        let at = |why: String| format!("{}: {why}", manifest_path.display());
        if m.v != 1 {
            return Err(at(format!("unsupported v {}", m.v)));
        }
        if m.build.len() != 16 || !m.build.bytes().all(is_lower_hex) {
            return Err(at("build must be 16 lower-case hex characters".into()));
        }
        if !m.files.contains_key(&m.sdk) {
            return Err(at(format!("sdk {:?} is not listed in files", m.sdk)));
        }
        if m.files.is_empty() || m.files.len() > 16 {
            return Err(at("files must list 1-16 files".into()));
        }
        if m.templates.len() != 1 || !m.templates.contains_key(TEMPLATE) {
            return Err(at(format!("templates must list exactly {TEMPLATE:?}")));
        }
        let mut files = BTreeMap::new();
        for (name, sha) in &m.files {
            if !is_file_name(name) || name == TEMPLATE || name == MANIFEST {
                return Err(at(format!(
                    "file name {name:?} is not [A-Za-z0-9._-]{{1,64}}"
                )));
            }
            let bytes = read_verified(dir, name, sha, MAX_FILE_BYTES)?;
            files.insert(name.clone(), Bytes::from(bytes));
        }
        let template = read_verified(dir, TEMPLATE, &m.templates[TEMPLATE], MAX_TEMPLATE_BYTES)?;
        let errors = validate_template(&template);
        if !errors.is_empty() {
            return Err(format!(
                "{}: violates the template contract (spec §11.2): {}",
                dir.join(TEMPLATE).display(),
                errors.join("; ")
            ));
        }
        let html = std::str::from_utf8(&template).map_err(|_| "template: not valid UTF-8")?;
        let template = Template::split(html)?;
        Ok(Self {
            build: m.build,
            sdk: m.sdk,
            files,
            template: Arc::new(template),
        })
    }

    /// The `src` of the SDK script on the challenge page (§11.2).
    pub fn sdk_src(&self) -> String {
        format!("/__mg/s/{}", self.sdk)
    }
}

fn read_capped(path: &Path, max: usize) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut buf = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if buf.len() > max {
        return Err(format!("{}: larger than {max} bytes", path.display()));
    }
    Ok(buf)
}

fn read_verified(dir: &Path, name: &str, sha: &str, max: usize) -> Result<Vec<u8>, String> {
    let path = dir.join(name);
    if sha.len() != 64 || !sha.bytes().all(is_lower_hex) {
        return Err(format!(
            "{}: manifest hash for {name:?} is not a lower-case SHA-256",
            dir.join(MANIFEST).display()
        ));
    }
    let bytes = read_capped(&path, max)?;
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if digest != sha {
        return Err(format!(
            "{}: SHA-256 does not match manifest.json",
            path.display()
        ));
    }
    Ok(bytes)
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

/// `[A-Za-z0-9._-]{1,64}` and not only dots (§10.4).
pub fn is_file_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !name.bytes().all(|b| b == b'.')
}

// ---------------------------------------------------------------------------
// validateTemplate (I-28)

/// ECMAScript `\s` (WhiteSpace and LineTerminator), also what
/// `String.prototype.trim` removes.
pub fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_space)
}

/// One attribute: lower-cased name, value (empty when absent) and, for a
/// quoted value, the byte span of its content in the whole template.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Attr {
    name: String,
    value: String,
    quoted: Option<(usize, usize)>,
}

/// One start tag matched by `TAG_PATTERN`.
#[derive(Debug, Clone)]
struct Tag {
    start: usize,
    end: usize,
    /// Lower-cased.
    name: String,
    attrs: Vec<Attr>,
}

impl Tag {
    /// The first attribute called `name` (`attributes.find`).
    fn get(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.value.as_str())
    }
}

/// `(?:[^>"']|"[^"]*"|'[^']*')*>` from byte `j`: the index just past the
/// closing `>`, or `None` (an unterminated quote or no `>`).
fn tag_end(b: &[u8], mut j: usize) -> Option<usize> {
    loop {
        match *b.get(j)? {
            b'>' => return Some(j + 1),
            q @ (b'"' | b'\'') => {
                let close = b.get(j + 1..)?.iter().position(|&x| x == q)?;
                j += close + 2;
            }
            _ => j += 1,
        }
    }
}

/// Every match of `TAG_PATTERN`, in document order.
fn scan_tags(html: &str) -> Vec<Tag> {
    let b = html.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'<' && b.get(i + 1).is_some_and(u8::is_ascii_alphabetic) {
            let mut j = i + 2;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'-') {
                j += 1;
            }
            if let Some(end) = tag_end(b, j) {
                out.push(Tag {
                    start: i,
                    end,
                    name: html[i + 1..j].to_lowercase(),
                    attrs: scan_attrs(&html[j..end - 1], j),
                });
                i = end;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn is_attr_name_char(c: char) -> bool {
    !is_js_space(c) && !matches!(c, '"' | '\'' | '=' | '<' | '>' | '/')
}

fn is_unquoted_value_char(c: char) -> bool {
    !is_js_space(c) && !matches!(c, '"' | '\'' | '=' | '<' | '>' | '`')
}

/// Skips ECMAScript whitespace from byte `i` of `s` (a char boundary).
fn skip_js_space(s: &str, mut i: usize) -> usize {
    while let Some(c) = s.get(i..).and_then(|r| r.chars().next()) {
        if !is_js_space(c) {
            break;
        }
        i += c.len_utf8();
    }
    i
}

/// Every match of `ATTRIBUTE_PATTERN` in `text`, which starts at byte
/// `offset` of the template.
fn scan_attrs(text: &str, offset: usize) -> Vec<Attr> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(c) = text[i..].chars().next() {
        if !is_attr_name_char(c) {
            i += c.len_utf8();
            continue;
        }
        let name_start = i;
        while let Some(c) = text[i..].chars().next() {
            if !is_attr_name_char(c) {
                break;
            }
            i += c.len_utf8();
        }
        let name = text[name_start..i].to_lowercase();
        // `(?:\s*=\s*(?:"…"|'…'|unquoted))?`: all or nothing.
        let mut value = String::new();
        let mut quoted = None;
        let k = skip_js_space(text, i);
        if text[k..].starts_with('=') {
            let v = skip_js_space(text, k + 1);
            match text[v..].chars().next() {
                Some(q @ ('"' | '\'')) => {
                    if let Some(close) = text[v + 1..].find(q) {
                        value = text[v + 1..v + 1 + close].to_owned();
                        quoted = Some((offset + v + 1, offset + v + 1 + close));
                        i = v + 1 + close + 1;
                    }
                }
                Some(c) if is_unquoted_value_char(c) => {
                    let mut e = v;
                    while let Some(c) = text[e..].chars().next() {
                        if !is_unquoted_value_char(c) {
                            break;
                        }
                        e += c.len_utf8();
                    }
                    value = text[v..e].to_owned();
                    i = e;
                }
                _ => {}
            }
        }
        out.push(Attr {
            name,
            value,
            quoted,
        });
    }
    out
}

/// Byte spans `[start, end)` of every `PLACEHOLDER_PATTERN` match
/// (`{{` + no brace + `}}`), in order.
pub fn placeholder_spans(html: &str) -> Vec<(usize, usize)> {
    let b = html.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == b'{' && b[i + 1] == b'{' {
            let mut j = i + 2;
            while j < b.len() && b[j] != b'{' && b[j] != b'}' {
                j += 1;
            }
            if j + 1 < b.len() && b[j] == b'}' && b[j + 1] == b'}' {
                out.push((i, j + 2));
                i = j + 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// ASCII case-insensitive `starts_with` at byte `i`.
fn starts_with_ci(b: &[u8], i: usize, pat: &[u8]) -> bool {
    b.get(i..i + pat.len())
        .is_some_and(|s| s.eq_ignore_ascii_case(pat))
}

/// Regions where no placeholder may appear: HTML comments, then the raw
/// text of `<script>` / `<style>` elements, as `(start, end, where)`.
fn forbidden_regions(html: &str) -> Vec<(usize, usize, String)> {
    let b = html.as_bytes();
    let mut out = Vec::new();
    // COMMENT_PATTERN: `<!--` up to the first `-->` after it, else the end.
    let mut i = 0;
    while let Some(off) = html[i..].find("<!--") {
        let start = i + off;
        let end = html[start + 4..]
            .find("-->")
            .map_or(b.len(), |e| start + 4 + e + 3);
        out.push((start, end, "inside an HTML comment".to_owned()));
        i = end;
    }
    // RAW_TEXT_PATTERN (case-insensitive).
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'<'
            && let Some((name, after_name)) = ["script", "style"].iter().find_map(|n| {
                let e = i + 1 + n.len();
                // `\b`: the next byte is not an ASCII word character.
                (starts_with_ci(b, i + 1, n.as_bytes())
                    && !b
                        .get(e)
                        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_'))
                .then_some((*n, e))
            })
            && let Some(content_start) = tag_end(b, after_name)
        {
            // Lazy content up to `</name\s*>`, or the end of the input.
            let mut found = None;
            let mut k = content_start;
            while k < b.len() {
                if b[k] == b'<'
                    && b.get(k + 1) == Some(&b'/')
                    && starts_with_ci(b, k + 2, name.as_bytes())
                {
                    let s = skip_js_space(html, k + 2 + name.len());
                    if b.get(s) == Some(&b'>') {
                        found = Some((k, s + 1));
                        break;
                    }
                }
                k += 1;
            }
            let (content_end, match_end) = found.unwrap_or((b.len(), b.len()));
            out.push((
                content_start,
                content_end,
                format!("inside <{name}> content"),
            ));
            i = match_end.max(i + 1);
            continue;
        }
        i += 1;
    }
    out
}

/// `placeholderContextErrors`: placeholders are allowed only inside a
/// quoted attribute value or in ordinary text. In an unquoted value, an
/// attribute or tag name, `<script>` / `<style>` content or a comment, the
/// §11.2 escaping would not keep a value such as `ret = "/a/;alert(1)//"`
/// from becoming markup or script.
fn placeholder_context_errors(html: &str, tags: &[Tag]) -> Vec<String> {
    let forbidden = forbidden_regions(html);
    let mut errors = Vec::new();
    for (start, end) in placeholder_spans(html) {
        let inner = &html[start + 2..end - 2];
        let within = |s: usize, e: usize| start >= s && end <= e;
        if let Some((_, _, place)) = forbidden.iter().find(|(s, e, _)| within(*s, *e)) {
            errors.push(format!("{{{{{inner}}}}} {place}"));
            continue;
        }
        if let Some(tag) = tags.iter().find(|t| within(t.start, t.end)) {
            let in_quotes = tag
                .attrs
                .iter()
                .filter_map(|a| a.quoted)
                .any(|(s, e)| within(s, e));
            if !in_quotes {
                errors.push(format!(
                    "{{{{{inner}}}}} outside a quoted attribute value in <{}>",
                    tag.name
                ));
            }
        } else if html[..start].ends_with('<') || html[..start].ends_with("</") {
            errors.push(format!("{{{{{inner}}}}} as a tag name"));
        }
    }
    errors
}

fn starts_external(value: &str) -> bool {
    let v = js_trim(value);
    ["//", "\\\\", "/\\", "\\/"]
        .iter()
        .any(|p| v.starts_with(p))
}

/// `/url\(\s*["']?\s*(?:\/\/|\\\\|\/\\)/i`.
fn has_protocol_relative_css_url(html: &str) -> bool {
    let b = html.as_bytes();
    (0..b.len()).any(|i| {
        if !starts_with_ci(b, i, b"url(") {
            return false;
        }
        let mut k = skip_js_space(html, i + 4);
        if matches!(b.get(k), Some(b'"' | b'\'')) {
            k = skip_js_space(html, k + 1);
        }
        ["//", "\\\\", "/\\"]
            .iter()
            .any(|p| b.get(k..k + 2) == Some(p.as_bytes()))
    })
}

/// `/<title>([^<]*)<\/title>/i.exec(html)?.[1]`.
fn first_title(html: &str) -> Option<&str> {
    let b = html.as_bytes();
    (0..b.len()).find_map(|i| {
        if !starts_with_ci(b, i, b"<title>") {
            return None;
        }
        let s = i + 7;
        let e = b[s..]
            .iter()
            .position(|&c| c == b'<')
            .map_or(b.len(), |p| s + p);
        starts_with_ci(b, e, b"</title>").then(|| &html[s..e])
    })
}

/// `html.replace(/<[^>]*>/g, "")`.
fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut i = 0;
    while let Some(off) = html[i..].find('<') {
        let lt = i + off;
        match html[lt..].find('>') {
            Some(gt) => {
                out.push_str(&html[i..lt]);
                i = lt + gt + 1;
            }
            None => break,
        }
    }
    out.push_str(&html[i..]);
    out
}

/// `data-mg-*` attributes of `<main id="mg-challenge">` and the placeholder
/// each must hold.
const MAIN_ATTRIBUTES: [(&str, &str); 7] = [
    ("data-mg-state", "{{state}}"),
    ("data-mg-c", "{{c}}"),
    ("data-mg-type", "{{type}}"),
    ("data-mg-pow-bits", "{{pow_bits}}"),
    ("data-mg-ret", "{{ret}}"),
    ("data-mg-rid", "{{request_id}}"),
    ("data-mg-prefix", "{{prefix}}"),
];

/// The §11.2 template contract, as `sdk/web/scripts/build-dist.mjs`
/// `validateTemplate` checks it (I-28): UTF-8, at most 32 KiB, a leading
/// `<!doctype html>`, exactly the known placeholders (each at least once, no
/// stray braces) and only in quoted attribute values or ordinary text, no
/// `http:` / `https:` / protocol-relative URL / CSS `@import`, no inline
/// event handler or `style` attribute, `nonce="{{nonce}}"` on every
/// `<script>` and `<style>`, the required structure, and one SDK
/// `<script>` with `data-cfasync="false"` before `src="{{sdk_src}}"` and
/// `data-mg-path-prefix="{{prefix}}"`. Returns every violation (empty =
/// valid).
pub fn validate_template(bytes: &[u8]) -> Vec<String> {
    let mut errors = Vec::new();
    if bytes.len() > MAX_TEMPLATE_BYTES {
        errors.push(format!(
            "larger than {MAX_TEMPLATE_BYTES} bytes ({})",
            bytes.len()
        ));
    }
    let Ok(html) = std::str::from_utf8(bytes) else {
        errors.push("not valid UTF-8".into());
        return errors;
    };
    if !starts_with_ci(html.as_bytes(), 0, b"<!doctype html>") {
        errors.push("must start with <!doctype html>".into());
    }

    // Placeholders: exactly the known set, each at least once, no stray braces.
    let spans = placeholder_spans(html);
    let mut seen = [false; PLACEHOLDERS.len()];
    for &(s, e) in &spans {
        let name = &html[s + 2..e - 2];
        match PLACEHOLDERS.iter().position(|p| *p == name) {
            Some(k) => seen[k] = true,
            None => errors.push(format!("unknown placeholder {{{{{name}}}}}")),
        }
    }
    for (k, name) in PLACEHOLDERS.iter().enumerate() {
        if !seen[k] {
            errors.push(format!("placeholder {{{{{name}}}}} missing"));
        }
    }
    let mut rest = String::with_capacity(html.len());
    let mut at = 0;
    for &(s, e) in &spans {
        rest.push_str(&html[at..s]);
        at = e;
    }
    rest.push_str(&html[at..]);
    if rest.contains("{{") || rest.contains("}}") {
        errors.push("stray {{ or }} outside a placeholder".into());
    }
    let tags = scan_tags(html);
    errors.extend(placeholder_context_errors(html, &tags));

    // External resources: no absolute or protocol-relative URLs anywhere.
    let lower = html.to_ascii_lowercase();
    if lower.contains("http:") || lower.contains("https:") {
        errors.push("contains an http: or https: URL".into());
    }
    if lower.contains("@import") {
        errors.push("contains a CSS @import".into());
    }
    if has_protocol_relative_css_url(html) {
        errors.push("contains a protocol-relative CSS url()".into());
    }

    for tag in &tags {
        for a in &tag.attrs {
            if starts_external(&a.value) {
                errors.push(format!(
                    "<{} {}> is a protocol-relative URL",
                    tag.name, a.name
                ));
            }
            // CSP allows only nonce'd <script> / <style>: inline handlers and
            // style attributes would be blocked.
            if a.name.starts_with("on") {
                errors.push(format!(
                    "<{}> has an inline event handler ({})",
                    tag.name, a.name
                ));
            }
            if a.name == "style" {
                errors.push(format!(
                    "<{}> has a style attribute (blocked by the nonce-only CSP)",
                    tag.name
                ));
            }
        }
        if (tag.name == "script" || tag.name == "style") && tag.get("nonce") != Some("{{nonce}}") {
            errors.push(format!("<{}> without nonce=\"{{{{nonce}}}}\"", tag.name));
        }
    }

    // Required structure.
    let count = |name: &str, pred: &dyn Fn(&Tag) -> bool| {
        tags.iter().filter(|t| t.name == name && pred(t)).count()
    };
    if count("html", &|t| t.get("lang") == Some("{{lang}}")) != 1 {
        errors.push("needs <html lang=\"{{lang}}\">".into());
    }
    if count("meta", &|t| {
        t.get("charset").map(str::to_lowercase).as_deref() == Some("utf-8")
    }) != 1
    {
        errors.push("needs <meta charset=\"utf-8\">".into());
    }
    if count("meta", &|t| {
        t.get("name") == Some("robots") && t.get("content") == Some("noindex")
    }) != 1
    {
        errors.push("needs <meta name=\"robots\" content=\"noindex\">".into());
    }
    if count("meta", &|t| {
        t.get("name") == Some("viewport")
            && t.get("content") == Some("width=device-width, initial-scale=1")
    }) != 1
    {
        errors.push(
            "needs <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">".into(),
        );
    }
    if first_title(html).is_none_or(|t| js_trim(t).is_empty()) {
        errors.push("needs a non-empty <title>".into());
    }
    if count("style", &|_| true) == 0 {
        errors.push("needs an inline <style>".into());
    }
    let main: Vec<&Tag> = tags
        .iter()
        .filter(|t| t.name == "main" && t.get("id") == Some("mg-challenge"))
        .collect();
    if main.len() != 1 {
        errors.push("needs exactly one <main id=\"mg-challenge\">".into());
    } else {
        for (name, value) in MAIN_ATTRIBUTES {
            if main[0].get(name) != Some(value) {
                errors.push(format!(
                    "<main id=\"mg-challenge\"> needs {name}=\"{value}\""
                ));
            }
        }
    }
    if count("p", &|t| {
        t.get("id") == Some("mg-status")
            && t.get("role") == Some("status")
            && t.get("aria-live") == Some("polite")
    }) != 1
    {
        errors.push("needs <p id=\"mg-status\" role=\"status\" aria-live=\"polite\">".into());
    }
    if count("a", &|t| {
        t.get("id") == Some("mg-retry")
            && t.get("href") == Some("{{ret}}")
            && t.get("hidden").is_some()
    }) != 1
    {
        errors.push("needs <a id=\"mg-retry\" href=\"{{ret}}\" hidden>".into());
    }
    if count("noscript", &|_| true) == 0 {
        errors.push("needs a <noscript> message".into());
    }
    if !strip_tags(html).contains("{{request_id}}") {
        errors.push("{{request_id}} must appear in the page text".into());
    }

    // The SDK script: nonce'd, Rocket Loader opt-out before src, path prefix.
    let external: Vec<&Tag> = tags
        .iter()
        .filter(|t| t.name == "script" && t.get("src").is_some())
        .collect();
    if external.len() != 1 || external[0].get("src") != Some("{{sdk_src}}") {
        errors.push("needs exactly one external <script>, src=\"{{sdk_src}}\"".into());
    } else {
        let script = external[0];
        let pos = |n: &str| script.attrs.iter().position(|a| a.name == n);
        // JS: `cfasync < 0 || cfasync > names.indexOf("src")` fails.
        let ordered = matches!((pos("data-cfasync"), pos("src")), (Some(a), Some(b)) if a <= b);
        if script.get("data-cfasync") != Some("false") || !ordered {
            errors.push("the SDK <script> needs data-cfasync=\"false\" before src".into());
        }
        if script.get("data-mg-path-prefix") != Some("{{prefix}}") {
            errors.push("the SDK <script> needs data-mg-path-prefix=\"{{prefix}}\"".into());
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sdk")
    }

    fn good() -> String {
        std::fs::read_to_string(fixture_dir().join(TEMPLATE)).unwrap()
    }

    #[test]
    fn loads_the_fixture_sdk() {
        let sdk = SdkDir::load(&fixture_dir()).unwrap();
        assert_eq!(sdk.build.len(), 16);
        assert_eq!(sdk.sdk, format!("mg.{}.js", sdk.build));
        assert!(sdk.files.contains_key(&sdk.sdk));
        assert_eq!(sdk.sdk_src(), format!("/__mg/s/{}", sdk.sdk));
        assert!(validate_template(good().as_bytes()).is_empty());
    }

    /// §16: the fixture is a copy of the SDK build (`sdk/web/dist/sdk/`),
    /// so the Edge is tested against what WP-W1 ships. Skipped when the SDK
    /// has not been built in this checkout (`dist/` is not committed).
    #[test]
    fn fixture_matches_the_sdk_build() {
        let dist = crate::test_support::repo("sdk/web/dist/sdk");
        let Ok(manifest) = std::fs::read(dist.join(MANIFEST)) else {
            eprintln!("SKIPPED: sdk/web/dist/sdk is not built");
            return;
        };
        assert_eq!(
            manifest,
            std::fs::read(fixture_dir().join(MANIFEST)).unwrap(),
            "edge/tests/fixtures/sdk is stale: copy sdk/web/dist/sdk/ into it"
        );
    }

    fn copy_fixture(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("mg-edge-sdk-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for e in std::fs::read_dir(fixture_dir()).unwrap() {
            let e = e.unwrap();
            std::fs::copy(e.path(), dir.join(e.file_name())).unwrap();
        }
        dir
    }

    #[test]
    fn rejects_tampered_files_and_bad_manifests() {
        let dir = copy_fixture("tamper");
        let sdk = SdkDir::load(&dir).unwrap();
        std::fs::write(dir.join(&sdk.sdk), b"alert(1)").unwrap();
        assert!(SdkDir::load(&dir).unwrap_err().contains("SHA-256"));
        let _ = std::fs::remove_dir_all(&dir);

        let dir = copy_fixture("manifest");
        let manifest = std::fs::read_to_string(dir.join(MANIFEST)).unwrap();
        for (from, to, needle) in [
            ("\"v\": 1", "\"v\": 2", "unsupported v"),
            ("\"build\"", "\"extra\": 1, \"build\"", "unknown field"),
            ("\"templates\"", "\"templatez\"", "unknown field"),
        ] {
            std::fs::write(dir.join(MANIFEST), manifest.replacen(from, to, 1)).unwrap();
            let e = SdkDir::load(&dir).unwrap_err();
            assert!(e.contains(needle), "{to}: {e}");
        }
        std::fs::write(
            dir.join(MANIFEST),
            manifest.replace(&sdk.sdk, "../../etc/passwd"),
        )
        .unwrap();
        assert!(SdkDir::load(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        assert!(SdkDir::load(Path::new("/nonexistent/sdk")).is_err());
    }

    /// A template breaking the contract is refused at load time even when
    /// the manifest hash matches it.
    #[test]
    fn load_refuses_a_template_that_breaks_the_contract() {
        let dir = copy_fixture("badtpl");
        let bad = good().replace(
            "data-mg-rid=\"{{request_id}}\"",
            "data-mg-rid={{request_id}}",
        );
        std::fs::write(dir.join(TEMPLATE), &bad).unwrap();
        let sha: String = Sha256::digest(bad.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let manifest = std::fs::read_to_string(dir.join(MANIFEST)).unwrap();
        let old = serde_json::from_str::<serde_json::Value>(&manifest).unwrap()["templates"]
            [TEMPLATE]
            .as_str()
            .unwrap()
            .to_owned();
        std::fs::write(dir.join(MANIFEST), manifest.replace(&old, &sha)).unwrap();
        let e = SdkDir::load(&dir).unwrap_err();
        assert!(e.contains("outside a quoted attribute value"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The rejection table of `sdk/web/test/template.test.ts`, case by case
    /// (I-28: the Edge's check equals `validateTemplate`).
    #[test]
    fn rejects_every_contract_violation_like_validate_template() {
        let t = good();
        let big = format!("<p>{}</p></body>", "x".repeat(32 * 1024));
        let cut = |from: &str, to: &str, with: &str| {
            let s = t.find(from).unwrap();
            let e = t.find(to).unwrap() + to.len();
            format!("{}{with}{}", &t[..s], &t[e..])
        };
        let cases: Vec<(&str, String, &str)> = vec![
            (
                "a missing placeholder",
                t.replace("{{state}}", "challenge"),
                "{{state}} missing",
            ),
            (
                "an unknown placeholder",
                t.replace("<noscript>", "<noscript>{{user}}"),
                "unknown placeholder {{user}}",
            ),
            (
                "stray braces",
                t.replace("<noscript>", "<noscript>{{"),
                "stray",
            ),
            (
                "a <script> without nonce",
                t.replace("</body>", "<script nonce=\"x\">1</script></body>"),
                "<script> without nonce",
            ),
            (
                "a <style> without nonce",
                t.replace("</head>", "<style>p{}</style></head>"),
                "<style> without nonce",
            ),
            (
                "an https URL",
                t.replace("<noscript>", "<noscript>https://example.com/"),
                "http: or https:",
            ),
            (
                "a protocol-relative src",
                t.replace("src=\"{{sdk_src}}\"", "src=\"//cdn.example/mg.js\""),
                "protocol-relative",
            ),
            (
                "a protocol-relative CSS url()",
                t.replacen(
                    "* { box-sizing",
                    ".x { background: url(//cdn.example/x.png) }\n* { box-sizing",
                    1,
                ),
                "url()",
            ),
            (
                "a CSS @import",
                t.replacen("* { box-sizing", "@import \"/x.css\";\n* { box-sizing", 1),
                "@import",
            ),
            (
                "data-cfasync after src",
                t.replace(
                    "<script data-cfasync=\"false\" src=\"{{sdk_src}}\"",
                    "<script src=\"{{sdk_src}}\" data-cfasync=\"false\"",
                ),
                "data-cfasync=\"false\" before src",
            ),
            (
                "a second external script",
                t.replace(
                    "</body>",
                    "<script nonce=\"{{nonce}}\" src=\"/x.js\"></script></body>",
                ),
                "exactly one external <script>",
            ),
            (
                "an inline event handler",
                t.replace("<a id=\"mg-retry\"", "<a onclick=\"x()\" id=\"mg-retry\""),
                "inline event handler",
            ),
            (
                "a style attribute",
                t.replace("<p class=\"rid\">", "<p class=\"rid\" style=\"color:red\">"),
                "style attribute",
            ),
            (
                "a missing main data attribute",
                t.replace("data-mg-type=\"{{type}}\"", "data-mg-kind=\"{{type}}\""),
                "data-mg-type",
            ),
            (
                "a missing retry link",
                t.replace("id=\"mg-retry\"", "id=\"retry\""),
                "mg-retry",
            ),
            (
                "a missing status region",
                t.replace("aria-live=\"polite\"", ""),
                "mg-status",
            ),
            (
                "a missing noscript",
                cut("<noscript>", "</noscript>", ""),
                "noscript",
            ),
            ("no doctype", t.replace("<!doctype html>", ""), "doctype"),
            (
                "no robots meta",
                t.replace("<meta name=\"robots\" content=\"noindex\">", ""),
                "robots",
            ),
            (
                "an empty title",
                cut("<title>", "</title>", "<title> </title>"),
                "title",
            ),
            (
                "request_id only in attributes",
                t.replace("<code>{{request_id}}</code>", "<code></code>"),
                "request_id",
            ),
            (
                "more than 32 KiB",
                t.replace("</body>", &big),
                "larger than",
            ),
            (
                "a placeholder in an unquoted attribute value",
                t.replace(
                    "data-mg-rid=\"{{request_id}}\"",
                    "data-mg-rid={{request_id}}",
                ),
                "outside a quoted attribute value",
            ),
            (
                "a placeholder as an attribute name",
                t.replace("<p class=\"rid\">", "<p class=\"rid\" {{ret}}>"),
                "outside a quoted attribute value",
            ),
            (
                "a placeholder in inline script",
                t.replace(
                    "</body>",
                    "<script nonce=\"{{nonce}}\">var r = {{ret}};</script></body>",
                ),
                "inside <script>",
            ),
            (
                "a placeholder in the stylesheet",
                t.replacen(
                    "* { box-sizing",
                    ".x::after { content: \"{{request_id}}\" }\n* { box-sizing",
                    1,
                ),
                "inside <style>",
            ),
            (
                "a placeholder in a comment",
                t.replace("<noscript>", "<!-- {{ret}} --><noscript>"),
                "inside an HTML comment",
            ),
            (
                "a placeholder as a tag name",
                t.replace("<noscript>", "<{{ret}}><noscript>"),
                "as a tag name",
            ),
        ];
        for (name, mutated, needle) in cases {
            assert_ne!(mutated, t, "{name}: the mutation did not apply");
            let errors = validate_template(mutated.as_bytes());
            assert!(
                errors.iter().any(|e| e.contains(needle)),
                "{name}: {needle:?} not in {errors:?}"
            );
        }
    }

    #[test]
    fn accepts_single_quoted_values_and_plain_text_placeholders() {
        let variant = good()
            .replace(
                "data-mg-rid=\"{{request_id}}\"",
                "data-mg-rid='{{request_id}}'",
            )
            .replace("<noscript>", "<p>{{request_id}}</p><noscript>");
        assert_eq!(validate_template(variant.as_bytes()), Vec::<String>::new());
    }

    #[test]
    fn invalid_utf8() {
        let mut bytes = good().into_bytes();
        bytes.push(0xff);
        assert!(
            validate_template(&bytes)
                .iter()
                .any(|e| e == "not valid UTF-8")
        );
        assert_eq!(validate_template(&[0xff, 0xfe]), ["not valid UTF-8"]);
    }

    /// JavaScript regex details the port reproduces.
    #[test]
    fn scanner_semantics() {
        // `{{{a}}` holds the placeholder `{{a}}` at index 1; `{{a}}}` at 0.
        assert_eq!(placeholder_spans("{{{a}}"), vec![(1, 6)]);
        assert_eq!(placeholder_spans("{{a}}}"), vec![(0, 5)]);
        assert!(placeholder_spans("{{a}b}}").is_empty());
        // An unterminated quote: no tag starts at that `<`, a later one does.
        let tags = scan_tags("<a title=\"x><b id='y'>");
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name, "b");
        assert_eq!(tags[0].get("id"), Some("y"));
        // A quoted `>` does not end a tag; names are lower-cased; the first
        // of two equal names wins; a bare name has an empty value.
        let tags = scan_tags("<P Title=\"a>b\" id=x ID=z hidden>");
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name, "p");
        assert_eq!(tags[0].get("title"), Some("a>b"));
        assert_eq!(tags[0].get("id"), Some("x"));
        assert_eq!(tags[0].get("hidden"), Some(""));
        // An unterminated quoted value: the name alone is the attribute.
        let attrs = scan_attrs(" a=\"x", 0);
        assert_eq!((attrs[0].name.as_str(), attrs[0].value.as_str()), ("a", ""));
        assert_eq!(attrs[1].name, "x");
        // Non-ASCII whitespace separates attributes (ECMAScript `\s`), and
        // quoted spans are absolute byte offsets.
        let attrs = scan_attrs("a=1\u{3000}b='2'", 10);
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[1].quoted, Some((10 + 9, 10 + 10)));
        // Raw text ends at `</script >` (whitespace allowed), case-insensitively.
        let r = forbidden_regions("<SCRIPT nonce='n'>x</script  >y<style>z");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].2, "inside <script> content");
        assert_eq!(r[1].2, "inside <style> content");
        assert!(forbidden_regions("<scripts>x</scripts>").is_empty());
        assert_eq!(forbidden_regions("<!-- a")[0].1, 6);
        assert_eq!(
            first_title("<title>a<b></title><TITLE>x</Title>"),
            Some("x")
        );
        assert_eq!(strip_tags("a<b>c<d"), "ac<d");
        assert!(has_protocol_relative_css_url("URL( ' //x"));
        assert!(!has_protocol_relative_css_url("url(/x)"));
        assert!(starts_external("\u{A0}//x"));
        assert!(!starts_external("/x"));
    }

    /// The pre-split template renders every placeholder escaped (§11.2).
    #[test]
    fn renders_escaped_values() {
        let sdk = SdkDir::load(&fixture_dir()).unwrap();
        let hostile = "\"><script>alert(1)</script><a href='//evil'>";
        let html = sdk.template.render(|_| hostile);
        assert!(!html.contains("{{") && !html.contains("}}"));
        assert!(!html.contains("<script>alert"));
        assert!(!html.contains("href='//evil'"));
        assert_eq!(
            scan_tags(&html)
                .iter()
                .filter(|t| t.name == "script")
                .count(),
            1
        );
        let html = sdk.template.render(|p| match p {
            Placeholder::Ret => "/account/login?next=%2Fcart&x=1",
            Placeholder::Nonce => "q83vEjRWeJq83vEjRWeJqw==",
            Placeholder::SdkSrc => "/__mg/s/mg.0123456789abcdef.js",
            _ => "v",
        });
        assert!(html.contains("data-mg-ret=\"/account/login?next=%2Fcart&amp;x=1\""));
        assert!(html.contains(
            "<script data-cfasync=\"false\" src=\"/__mg/s/mg.0123456789abcdef.js\" nonce=\"q83vEjRWeJq83vEjRWeJqw==\""
        ));
        let mut out = String::new();
        escape_html_into("&<>\"'x", &mut out);
        assert_eq!(out, "&amp;&lt;&gt;&quot;&#39;x");
    }

    /// §2.4 item 3: the template checker never panics (10,000 xorshift
    /// inputs: random bytes, and local edits of the real template).
    #[test]
    fn random_templates_never_panic() {
        let good = good().into_bytes();
        let mut s = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        const ALPHABET: &[u8] = b"<>\"'={}/ a-!\\`\xc3\xa9\xe3\x80\x80";
        for i in 0..10_000 {
            let mut t: Vec<u8> = if i % 3 == 0 {
                let len = (next() % 512) as usize;
                (0..len).map(|_| (next() >> 24) as u8).collect()
            } else {
                good.clone()
            };
            for _ in 0..6 {
                if t.is_empty() {
                    break;
                }
                let r = next();
                let at = (r as usize) % t.len();
                t[at] = ALPHABET[(r >> 32) as usize % ALPHABET.len()];
            }
            if validate_template(&t).is_empty() {
                let html = std::str::from_utf8(&t).unwrap();
                assert!(Template::split(html).is_ok());
            }
        }
    }
}
