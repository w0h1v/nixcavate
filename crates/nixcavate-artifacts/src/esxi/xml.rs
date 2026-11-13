//! A small, tolerant XML reader for the plain configuration files ESXi keeps (`vmInventory.xml`,
//! `authorization.xml`, VIB descriptors, firewall rule sets). They are machine-written, have no
//! namespaces and no DTD, so this reads only elements, attributes, text and CDATA; comments,
//! processing instructions and a DOCTYPE are skipped, and only the five predefined entities
//! and numeric references are decoded. Nesting depth and node count are capped, so hostile
//! input cannot exhaust the stack or memory. A document that ends early yields what was read.

use std::borrow::Cow;

/// Deeper nesting than any ESXi file has: the rest of the document is not read.
const MAX_DEPTH: usize = 64;
/// More elements than any ESXi file has (the largest, `vmconfigoption-*.xml`, is not read).
const MAX_NODES: usize = 400_000;

#[derive(Debug, Default)]
pub struct Node<'a> {
    pub name: &'a str,
    attrs: &'a str,
    /// The text directly inside the element, trimmed and with entities decoded.
    pub text: Cow<'a, str>,
    pub children: Vec<Node<'a>>,
}

impl<'a> Node<'a> {
    /// The first child element with this name.
    pub fn child(&self, name: &str) -> Option<&Node<'a>> {
        self.children.iter().find(|c| c.name == name)
    }

    /// The text of the first child with this name, empty when absent.
    pub fn child_text(&self, name: &str) -> &str {
        self.child(name).map_or("", |c| &c.text)
    }

    pub fn children_named<'s>(&'s self, name: &'s str) -> impl Iterator<Item = &'s Node<'a>> + 's {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// An attribute value (`id='0007'`), decoded.
    pub fn attr(&self, key: &str) -> Option<Cow<'a, str>> {
        let mut rest = self.attrs;
        loop {
            rest = rest.trim_start();
            let eq = rest.find('=')?;
            let name = rest[..eq].trim();
            let after = rest[eq + 1..].trim_start();
            let quote = after.chars().next().filter(|q| matches!(q, '\'' | '"'))?;
            let body = &after[1..];
            let end = body.find(quote)?;
            if name == key {
                return Some(decode(&body[..end]));
            }
            rest = &body[end + 1..];
        }
    }
}

/// The outcome of reading a document.
pub struct Document<'a> {
    pub root: Node<'a>,
    /// A limit was reached or the document was cut: `root` holds only what came before.
    pub incomplete: bool,
}

/// Reads `text` into a tree whose root is a synthetic node holding the document's elements.
pub fn parse(text: &str) -> Document<'_> {
    let mut stack: Vec<Node> = vec![Node::default()];
    let mut nodes = 0usize;
    let mut incomplete = false;
    let bytes = text.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        let Some(open) = memchr::memchr(b'<', &bytes[pos..]).map(|i| pos + i) else {
            add_text(&mut stack, &text[pos..]);
            break;
        };
        add_text(&mut stack, &text[pos..open]);
        let rest = &text[open..];
        if let Some(body) = rest.strip_prefix("<!--") {
            match body.find("-->") {
                Some(end) => pos = open + 4 + end + 3,
                None => {
                    incomplete = true;
                    break;
                }
            }
            continue;
        }
        if let Some(body) = rest.strip_prefix("<![CDATA[") {
            let end = body.find("]]>");
            let cdata = &body[..end.unwrap_or(body.len())];
            if let Some(top) = stack.last_mut() {
                top.text = Cow::Owned(format!("{}{cdata}", top.text));
            }
            match end {
                Some(end) => pos = open + 9 + end + 3,
                None => {
                    incomplete = true;
                    break;
                }
            }
            continue;
        }
        let Some(close) = tag_end(rest) else {
            incomplete = true;
            break;
        };
        pos = open + close + 1;
        let inner = &rest[1..close];
        if inner.starts_with('?') || inner.starts_with('!') {
            continue;
        }
        if let Some(name) = inner.strip_prefix('/') {
            // An end tag closes the nearest open element of that name; a stray one is ignored.
            let name = name.trim();
            if let Some(depth) = stack.iter().rposition(|n| n.name == name).filter(|&d| d > 0) {
                while stack.len() > depth {
                    pop(&mut stack);
                }
            }
            continue;
        }
        let empty = inner.ends_with('/');
        let inner = inner.strip_suffix('/').unwrap_or(inner);
        let (name, attrs) = inner.split_once(|c: char| c.is_whitespace()).unwrap_or((inner, ""));
        nodes += 1;
        if nodes > MAX_NODES || stack.len() > MAX_DEPTH {
            incomplete = true;
            break;
        }
        stack.push(Node { name, attrs, text: Cow::Borrowed(""), children: Vec::new() });
        if empty {
            pop(&mut stack);
        }
    }
    // Elements still open when the text ended are closed as they stand.
    if stack.len() > 1 {
        incomplete = true;
    }
    while stack.len() > 1 {
        pop(&mut stack);
    }
    Document { root: stack.pop().unwrap_or_default(), incomplete }
}

fn pop(stack: &mut Vec<Node>) {
    if let Some(done) = stack.pop() {
        if let Some(parent) = stack.last_mut() {
            parent.children.push(done);
        }
    }
}

fn add_text<'a>(stack: &mut [Node<'a>], text: &'a str) {
    let text = text.trim();
    if text.is_empty() {
        return;
    }
    if let Some(top) = stack.last_mut() {
        let decoded = decode(text);
        top.text = if top.text.is_empty() { decoded } else { Cow::Owned(format!("{} {decoded}", top.text)) };
    }
}

/// The index of the `>` that ends the tag starting at `rest[0]`, skipping quoted attribute values.
fn tag_end(rest: &str) -> Option<usize> {
    let mut quote = None;
    for (i, b) in rest.bytes().enumerate() {
        match (quote, b) {
            (Some(q), b) if b == q => quote = None,
            (Some(_), _) => {}
            (None, b'\'' | b'"') => quote = Some(b),
            (None, b'>') => return Some(i),
            _ => {}
        }
    }
    None
}

fn decode(text: &str) -> Cow<'_, str> {
    if !text.contains('&') {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let entity = rest.find(';').filter(|&end| end <= 10).map(|end| (&rest[1..end], end));
        let replacement = entity.and_then(|(name, _)| match name {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => {
                let number = name.strip_prefix('#')?;
                let code = match number.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                    None => number.parse().ok()?,
                };
                char::from_u32(code)
            }
        });
        match (replacement, entity) {
            (Some(c), Some((_, end))) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            _ => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_elements_attributes_text_and_entities() {
        let doc =
            parse("<?xml version='1.0'?><!-- c --><a x='1' y=\"b&amp;c\"><b>t &lt;1&gt; &#65;</b><c/><b>2</b></a>");
        assert!(!doc.incomplete);
        let a = doc.root.child("a").unwrap();
        assert_eq!(a.attr("x").as_deref(), Some("1"));
        assert_eq!(a.attr("y").as_deref(), Some("b&c"));
        assert_eq!(a.child_text("b"), "t <1> A");
        assert_eq!(a.children_named("b").count(), 2);
        assert!(a.child("c").is_some_and(|c| c.children.is_empty()));
    }

    #[test]
    fn cut_or_hostile_documents_give_what_was_read() {
        let doc = parse("<a><b>text</b><c>unfinished");
        assert!(doc.incomplete);
        assert_eq!(doc.root.child("a").unwrap().child_text("b"), "text");
        let deep = "<a>".repeat(10_000);
        assert!(parse(&deep).incomplete);
        let wide = "<a/>".repeat(MAX_NODES + 10);
        assert!(parse(&wide).incomplete);
        for cut in ["<", "<a", "<a x='", "<!--", "<![CDATA[x", "&", "<a>&#xZZ;&bad", "</a></a>"] {
            parse(cut);
        }
    }
}
