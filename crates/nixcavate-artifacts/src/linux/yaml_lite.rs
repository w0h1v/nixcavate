//! A small reader for the block-style YAML that Kubernetes tooling and agents write by hand or
//! generate (static pod manifests, kubeconfigs, kubelet configuration, `ngrok.yml`,
//! `cloudflared` configs). It returns a `serde_json::Value`, so one fact extractor serves JSON
//! and YAML. The crate has no YAML dependency and the parsers that need one only need these
//! shapes, so this is deliberately not a YAML implementation.
//!
//! Supported: block mappings and sequences (a sequence may sit at its key's indentation), plain
//! and quoted scalars (booleans and decimal integers are typed), literal and folded block
//! scalars (`|`, `>`), flow sequences and mappings (several lines), comments, `&anchors` and
//! `!tags` (ignored), several documents split by [`split_documents`].
//!
//! Not supported, and reported as an error so that nothing is silently misread: aliases
//! (`*name`) and merge keys (`<<`), tab indentation, multi-line plain or quoted scalars, complex
//! keys (`? `), nesting deeper than [`MAX_DEPTH`] and more than [`MAX_NODES`] values.

use serde_json::{Map, Number, Value};

/// The deepest nesting read; real manifests are under twenty levels.
pub const MAX_DEPTH: usize = 40;
/// The most values one document may hold.
pub const MAX_NODES: usize = 100_000;
/// A flow collection that continues over this many lines is not read.
const MAX_FLOW_LINES: usize = 64;

/// Documents of a multi-document stream: the line number (0-based) each starts at and its text.
/// The separator lines are not part of any document.
pub fn split_documents(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let (mut start, mut first_line, mut line_no) = (0usize, 0usize, 0usize);
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let end = offset + line.len();
        let bare = line.trim_end();
        let separator = bare == "---" || bare.starts_with("--- ") || bare == "...";
        if separator {
            out.push((first_line, &text[start..offset]));
            start = end;
            first_line = line_no + 1;
        }
        offset = end;
        line_no += 1;
    }
    out.push((first_line, &text[start..]));
    out.retain(|(_, doc)| doc.lines().any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#')));
    out
}

struct Line<'a> {
    /// Index into the source lines, for block scalars that read them raw.
    no: usize,
    indent: usize,
    text: &'a str,
}

struct Parser<'a> {
    source: Vec<&'a str>,
    lines: Vec<Line<'a>>,
    pos: usize,
    nodes: usize,
}

/// Parses one YAML document into a value. An empty document is `null`.
pub fn parse(text: &str) -> Result<Value, String> {
    let source: Vec<&str> = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).collect();
    let mut lines = Vec::new();
    for (no, raw) in source.iter().enumerate() {
        let trimmed = raw.trim_start_matches(' ');
        if trimmed.starts_with('\t') {
            return Err(format!("line {}: tab indentation is not supported", no + 1));
        }
        let text = strip_comment(trimmed).trim_end();
        if text.is_empty() {
            continue;
        }
        lines.push(Line { no, indent: raw.len() - trimmed.len(), text });
    }
    let mut parser = Parser { source, lines, pos: 0, nodes: 0 };
    if parser.lines.is_empty() {
        return Ok(Value::Null);
    }
    let value = parser.node(0, 0)?;
    match parser.lines.get(parser.pos) {
        Some(line) => Err(format!("line {}: unexpected content at this indentation", line.no + 1)),
        None => Ok(value),
    }
}

/// The text without a trailing comment (a `#` at the start or after a space, outside quotes).
fn strip_comment(text: &str) -> &str {
    let bytes = text.as_bytes();
    let mut quote = 0u8;
    // Whether a quote opened here would start a token: only then is it a quote at all.
    let mut token_start = true;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if quote != 0 {
            if b == b'\\' && quote == b'"' {
                i += 1;
            } else if b == quote {
                quote = 0;
            }
        } else if (b == b'"' || b == b'\'') && token_start {
            quote = b;
        } else if b == b'#' && (i == 0 || bytes[i - 1] == b' ') {
            return text.get(..i).unwrap_or(text);
        }
        token_start = quote == 0 && matches!(b, b' ' | b':' | b'-' | b'[' | b'{' | b',');
        i += 1;
    }
    text
}

fn is_dash(text: &str) -> bool {
    text == "-" || text.starts_with("- ")
}

/// Splits `key: value` at the first `: ` (or a final `:`) outside quotes. The key is unquoted.
fn split_key(text: &str) -> Option<(String, &str)> {
    let bytes = text.as_bytes();
    if matches!(bytes.first(), Some(b'"' | b'\'')) {
        let (key, rest) = quoted(text)?;
        let rest = rest.trim_start_matches(' ');
        let value = rest.strip_prefix(':')?;
        return (value.is_empty() || value.starts_with(' ')).then(|| (key, value.trim_start()));
    }
    if matches!(bytes.first(), Some(b'[' | b'{' | b'?' | b'*')) {
        return None;
    }
    let mut at = 0;
    while let Some(found) = text.get(at..).and_then(|t| t.find(':')) {
        let colon = at + found;
        let after = text.get(colon + 1..)?;
        if after.is_empty() || after.starts_with(' ') {
            return Some((text.get(..colon)?.trim_end().to_string(), after.trim_start()));
        }
        at = colon + 1;
    }
    None
}

/// A quoted scalar at the start of `text`: its value and the text after the closing quote.
fn quoted(text: &str) -> Option<(String, &str)> {
    let mut chars = text.char_indices();
    let (_, quote) = chars.next()?;
    let mut out = String::new();
    while let Some((i, c)) = chars.next() {
        if quote == '\'' {
            if c == '\'' {
                if text.get(i + 1..)?.starts_with('\'') {
                    out.push('\'');
                    chars.next();
                } else {
                    return Some((out, text.get(i + 1..)?));
                }
            } else {
                out.push(c);
            }
        } else if c == '"' {
            return Some((out, text.get(i + 1..)?));
        } else if c == '\\' {
            match chars.next()?.1 {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                '0' => out.push('\0'),
                'x' => out.push(hex_char(&mut chars, 2)?),
                'u' => out.push(hex_char(&mut chars, 4)?),
                other => out.push(other),
            }
        } else {
            out.push(c);
        }
    }
    None
}

fn hex_char(chars: &mut std::str::CharIndices, digits: usize) -> Option<char> {
    let mut value = 0u32;
    for _ in 0..digits {
        value = value.checked_mul(16)?.checked_add(chars.next()?.1.to_digit(16)?)?;
    }
    char::from_u32(value)
}

/// A scalar as YAML's core schema types it, for the cases that matter here.
fn scalar(text: &str) -> Result<Value, String> {
    let text = text.trim();
    if text.starts_with('"') || text.starts_with('\'') {
        let (value, rest) = quoted(text).ok_or("unterminated quoted scalar")?;
        return if rest.trim().is_empty() {
            Ok(Value::String(value))
        } else {
            Err("text after a quoted scalar".into())
        };
    }
    if text.starts_with('*') {
        return Err("aliases (*name) are not supported".into());
    }
    Ok(match text {
        "" | "~" | "null" | "Null" | "NULL" => Value::Null,
        "true" | "True" | "TRUE" => Value::Bool(true),
        "false" | "False" | "FALSE" => Value::Bool(false),
        _ => {
            let digits = text.strip_prefix(['-', '+']).unwrap_or(text);
            let plain_int = !digits.is_empty()
                && digits.len() <= 18
                && digits.bytes().all(|b| b.is_ascii_digit())
                && (digits == "0" || !digits.starts_with('0'));
            match (plain_int, text.parse::<i64>()) {
                (true, Ok(n)) => Value::Number(Number::from(n)),
                _ => Value::String(text.to_string()),
            }
        }
    })
}

/// Drops a leading `&anchor` or `!tag` token.
fn strip_decorations(mut text: &str) -> &str {
    while text.starts_with('&') || text.starts_with('!') {
        text = text.split_once(' ').map_or("", |(_, rest)| rest.trim_start());
    }
    text
}

impl Parser<'_> {
    fn count(&mut self) -> Result<(), String> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(format!("more than {MAX_NODES} values"));
        }
        Ok(())
    }

    /// The value starting at the current line, which must be indented at least `min`.
    fn node(&mut self, min: usize, depth: usize) -> Result<Value, String> {
        if depth > MAX_DEPTH {
            return Err(format!("nesting deeper than {MAX_DEPTH} levels"));
        }
        let Some(line) = self.lines.get(self.pos) else { return Ok(Value::Null) };
        let (indent, text) = (line.indent, line.text);
        if indent < min {
            return Ok(Value::Null);
        }
        if is_dash(text) {
            self.sequence(indent, depth)
        } else if split_key(text).is_some() {
            self.mapping(indent, depth)
        } else {
            self.count()?;
            self.pos += 1;
            scalar(strip_decorations(text))
        }
    }

    fn sequence(&mut self, indent: usize, depth: usize) -> Result<Value, String> {
        let mut items = Vec::new();
        while let Some(line) = self.lines.get(self.pos) {
            if line.indent != indent || !is_dash(line.text) {
                break;
            }
            let (text, no) = (line.text, line.no);
            self.count()?;
            let content = text.get(1..).unwrap_or("");
            let body = content.trim_start_matches(' ');
            if body.is_empty() {
                self.pos += 1;
                let next_deeper = self.lines.get(self.pos).is_some_and(|l| l.indent > indent);
                items.push(if next_deeper { self.node(indent + 1, depth + 1)? } else { Value::Null });
            } else if body.starts_with('|') || body.starts_with('>') {
                items.push(self.block_scalar(body, indent, no));
            } else {
                // The item's content starts further right on the same line: re-read the line as
                // that content, indented to where it starts.
                let column = indent + 1 + (content.len() - body.len());
                if let Some(line) = self.lines.get_mut(self.pos) {
                    line.indent = column;
                    line.text = body;
                }
                items.push(self.node(column, depth + 1)?);
            }
        }
        Ok(Value::Array(items))
    }

    fn mapping(&mut self, indent: usize, depth: usize) -> Result<Value, String> {
        let mut map = Map::new();
        while let Some(line) = self.lines.get(self.pos) {
            if line.indent != indent || is_dash(line.text) {
                break;
            }
            let (text, no) = (line.text, line.no);
            let Some((key, rest)) = split_key(text) else {
                return Err(format!("line {}: expected `key: value`", no + 1));
            };
            if key == "<<" {
                return Err("merge keys (<<) are not supported".into());
            }
            self.count()?;
            let rest = strip_decorations(rest);
            let value = if rest.is_empty() {
                self.pos += 1;
                match self.lines.get(self.pos) {
                    Some(next) if next.indent > indent => self.node(indent + 1, depth + 1)?,
                    Some(next) if next.indent == indent && is_dash(next.text) => self.sequence(indent, depth + 1)?,
                    _ => Value::Null,
                }
            } else if rest.starts_with('|') || rest.starts_with('>') {
                self.block_scalar(rest, indent, no)
            } else if rest.starts_with('[') || rest.starts_with('{') {
                self.flow_value(rest, no)?
            } else {
                self.pos += 1;
                scalar(rest).map_err(|e| format!("line {}: {e}", no + 1))?
            };
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }

    /// A literal (`|`) or folded (`>`) scalar: the raw lines indented deeper than its key.
    fn block_scalar(&mut self, header: &str, key_indent: usize, key_no: usize) -> Value {
        let folded = header.starts_with('>');
        let keep_end = header.contains('+');
        let strip_end = header.contains('-');
        let mut body: Vec<&str> = Vec::new();
        let mut last = key_no;
        let mut block_indent = None;
        for (no, raw) in self.source.iter().enumerate().skip(key_no + 1) {
            let indent = raw.len() - raw.trim_start_matches(' ').len();
            if raw.trim().is_empty() {
                body.push("");
                continue;
            }
            if indent <= key_indent {
                break;
            }
            let base = *block_indent.get_or_insert(indent);
            body.push(raw.get(base.min(indent)..).unwrap_or(""));
            last = no;
        }
        // Trailing blank lines belong to the block only for `|+`.
        let used = if keep_end { body.len() } else { last.saturating_sub(key_no) };
        body.truncate(used);
        let text = if folded { body.join(" ") } else { body.join("\n") };
        let text = if strip_end || keep_end { text } else { format!("{text}\n") };
        self.pos = self.lines.iter().position(|l| l.no > last).unwrap_or(self.lines.len());
        Value::String(if text == "\n" { String::new() } else { text })
    }

    /// A flow collection that may continue over following lines until its brackets balance.
    fn flow_value(&mut self, first: &str, no: usize) -> Result<Value, String> {
        let mut text = first.to_string();
        let mut last = no;
        let mut taken = 0;
        while !balanced(&text) {
            taken += 1;
            let next = self
                .lines
                .iter()
                .find(|l| l.no > last)
                .ok_or_else(|| format!("line {}: unterminated flow collection", no + 1))?;
            if taken > MAX_FLOW_LINES {
                return Err(format!("line {}: flow collection longer than {MAX_FLOW_LINES} lines", no + 1));
            }
            text.push(' ');
            text.push_str(next.text);
            last = next.no;
        }
        self.pos = self.lines.iter().position(|l| l.no > last).unwrap_or(self.lines.len());
        let mut flow = Flow { bytes: text.as_bytes(), at: 0, nodes: &mut self.nodes };
        let value = flow.value(0)?;
        flow.skip_space();
        if flow.at != flow.bytes.len() {
            return Err(format!("line {}: text after a flow collection", no + 1));
        }
        Ok(value)
    }
}

/// True when every `[`/`{` outside quotes has been closed.
fn balanced(text: &str) -> bool {
    let (mut depth, mut quote) = (0i32, 0u8);
    let mut escaped = false;
    for &b in text.as_bytes() {
        if quote != 0 {
            if escaped {
                escaped = false;
            } else if b == b'\\' && quote == b'"' {
                escaped = true;
            } else if b == quote {
                quote = 0;
            }
        } else {
            match b {
                b'"' | b'\'' => quote = b,
                b'[' | b'{' => depth += 1,
                b']' | b'}' => depth -= 1,
                _ => {}
            }
        }
    }
    depth <= 0
}

struct Flow<'a> {
    bytes: &'a [u8],
    at: usize,
    nodes: &'a mut usize,
}

impl Flow<'_> {
    fn skip_space(&mut self) {
        while self.bytes.get(self.at).is_some_and(|b| b.is_ascii_whitespace()) {
            self.at += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MAX_DEPTH {
            return Err(format!("nesting deeper than {MAX_DEPTH} levels"));
        }
        *self.nodes += 1;
        if *self.nodes > MAX_NODES {
            return Err(format!("more than {MAX_NODES} values"));
        }
        self.skip_space();
        match self.bytes.get(self.at) {
            Some(b'[') => {
                self.at += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_space();
                    match self.bytes.get(self.at) {
                        Some(b']') => {
                            self.at += 1;
                            return Ok(Value::Array(items));
                        }
                        Some(b',') => self.at += 1,
                        Some(_) => {
                            let before = self.at;
                            items.push(self.value(depth + 1)?);
                            if self.at == before {
                                return Err("unexpected character in a flow sequence".into());
                            }
                        }
                        None => return Err("unterminated flow sequence".into()),
                    }
                }
            }
            Some(b'{') => {
                self.at += 1;
                let mut map = Map::new();
                loop {
                    self.skip_space();
                    match self.bytes.get(self.at) {
                        Some(b'}') => {
                            self.at += 1;
                            return Ok(Value::Object(map));
                        }
                        Some(b',') => self.at += 1,
                        Some(_) => {
                            let before = self.at;
                            let key = self.token(true)?;
                            if self.at == before {
                                return Err("unexpected character in a flow mapping".into());
                            }
                            self.skip_space();
                            if self.bytes.get(self.at) == Some(&b':') {
                                self.at += 1;
                                let value = self.value(depth + 1)?;
                                map.insert(key, value);
                            } else {
                                map.insert(key, Value::Null);
                            }
                        }
                        None => return Err("unterminated flow mapping".into()),
                    }
                }
            }
            Some(_) => {
                let text = self.token(false)?;
                scalar(&text)
            }
            None => Err("unexpected end of a flow collection".into()),
        }
    }

    /// A scalar token up to `,` `]` `}` (and `:` for a key), quotes kept for the scalar reader.
    fn token(&mut self, key: bool) -> Result<String, String> {
        self.skip_space();
        let start = self.at;
        let mut quote = 0u8;
        while let Some(&b) = self.bytes.get(self.at) {
            if quote != 0 {
                if b == b'\\' && quote == b'"' {
                    self.at += 1;
                } else if b == quote {
                    quote = 0;
                }
            } else if (b == b'"' || b == b'\'') && self.at == start {
                quote = b;
            } else if matches!(b, b',' | b']' | b'}') || (key && b == b':' && self.next_is_space()) {
                break;
            }
            self.at += 1;
        }
        let raw = self.bytes.get(start..self.at.min(self.bytes.len())).unwrap_or_default();
        let text = String::from_utf8_lossy(raw).trim().to_string();
        if key {
            let unquoted = quoted(&text).map(|(k, _)| k);
            return Ok(unquoted.unwrap_or(text));
        }
        Ok(text)
    }

    fn next_is_space(&self) -> bool {
        self.bytes.get(self.at + 1).is_none_or(|b| b.is_ascii_whitespace() || *b == b',')
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn block_structures_and_scalars() {
        let doc = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web # the name\n  labels: {app: web, tier: \"front end\"}\nspec:\n  hostNetwork: true\n  containers:\n  - name: a\n    image: nginx:1.27\n    args: [\"--port\", 80]\n    command:\n      - sh\n      - -c\n      - |\n        echo one\n        echo two\n  - name: b\n    image: busybox\n";
        let v = parse(doc).unwrap();
        assert_eq!(v["metadata"]["name"], "web");
        assert_eq!(v["metadata"]["labels"], json!({"app": "web", "tier": "front end"}));
        assert_eq!(v["spec"]["hostNetwork"], true);
        assert_eq!(v["spec"]["containers"][0]["args"], json!(["--port", 80]));
        assert_eq!(v["spec"]["containers"][0]["command"], json!(["sh", "-c", "echo one\necho two\n"]));
        assert_eq!(v["spec"]["containers"][1]["image"], "busybox");
    }

    #[test]
    fn sequences_at_the_keys_indentation_and_nested_dashes() {
        let v = parse("a:\n- x: 1\n  y: 2\n- - p\n  - q\nb: ''\nc: 'it''s'\n").unwrap();
        assert_eq!(v, json!({"a": [{"x": 1, "y": 2}, ["p", "q"]], "b": "", "c": "it's"}));
    }

    #[test]
    fn urls_colons_and_quoted_keys() {
        let v = parse("server: https://127.0.0.1:6443\n\"quoted key\": v: w\nref: a:b\n").unwrap();
        assert_eq!(v["server"], "https://127.0.0.1:6443");
        assert_eq!(v["quoted key"], "v: w");
        assert_eq!(v["ref"], "a:b");
    }

    #[test]
    fn unsupported_constructs_are_errors_not_guesses() {
        assert!(parse("a: &x 1\nb: *x\n").is_err());
        assert!(parse("<<: *base\n").is_err());
        assert!(parse("a:\n\tb: 1\n").is_err());
        assert!(parse("a: [1, 2\n").is_err());
        assert!(parse("a: \"open\n").is_err());
        let deep = (0..60).map(|i| format!("{}k: \n", " ".repeat(i))).collect::<String>();
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn documents_split_on_separators() {
        let docs = split_documents("a: 1\n---\nb: 2\n---\n# nothing\n---\nc: 3\n");
        assert_eq!(docs.iter().map(|(_, d)| d.trim()).collect::<Vec<_>>(), ["a: 1", "b: 2", "c: 3"]);
        assert_eq!(docs[1].0, 2);
    }

    /// Any byte string must give a value or an error, never a panic or a hang.
    #[test]
    fn mutated_documents_never_panic() {
        let seed = "a: 1\nb:\n  - c: [1, {d: \"e\"}]\n  - |\n    text\nf: 'g'\n# x\nh: &i !!str j\n";
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet = b" \n:-[]{},\"'#|>&*!?\t\\x0";
        for round in 0..4000 {
            let mut bytes = seed.as_bytes().to_vec();
            for _ in 0..=(round % 6) {
                let at = (next() as usize) % bytes.len();
                bytes[at] = alphabet[(next() as usize) % alphabet.len()];
            }
            if round % 5 == 0 {
                bytes.truncate((next() as usize) % bytes.len());
            }
            let _ = parse(&String::from_utf8_lossy(&bytes));
        }
        let long = "- ".repeat(5000);
        let _ = parse(&long);
        let _ = parse(&"[".repeat(5000));
    }
}
