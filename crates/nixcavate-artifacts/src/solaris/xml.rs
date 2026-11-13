//! A small XML tokenizer for the two XML formats the Solaris artifacts read (SMF manifests and
//! IPS history). It does not build a tree and does not validate: it yields tags, attributes and
//! text, decodes the five predefined entities and numeric references, and stops at the first
//! construct it cannot read. Nothing is allocated unless an attribute holds an entity. The
//! consumer tracks nesting; the tokenizer itself has no depth.

use std::borrow::Cow;

pub enum Token<'a> {
    /// `<name a="b">`; `empty` is true for `<name a="b"/>`.
    Start {
        name: &'a str,
        attrs: Vec<(&'a str, Cow<'a, str>)>,
        empty: bool,
    },
    End(&'a str),
    Text(Cow<'a, str>),
}

pub struct Tokens<'a> {
    text: &'a str,
    at: usize,
    failed: bool,
}

/// The most attributes read from one tag; the rest are ignored.
const MAX_ATTRS: usize = 64;

pub fn tokens(text: &str) -> Tokens<'_> {
    Tokens { text, at: 0, failed: false }
}

impl Tokens<'_> {
    /// True when the tokenizer stopped at something it could not read, not at the end.
    pub fn failed(&self) -> bool {
        self.failed
    }
}

impl<'a> Iterator for Tokens<'a> {
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Token<'a>> {
        loop {
            let rest = self.text.get(self.at..)?;
            if rest.is_empty() || self.failed {
                return None;
            }
            if !rest.starts_with('<') {
                let end = rest.find('<').unwrap_or(rest.len());
                self.at += end;
                let text = &rest[..end];
                if text.trim().is_empty() {
                    continue;
                }
                return Some(Token::Text(decode(text.trim())));
            }
            // CDATA is text, taken as written (no entities, not trimmed: IPS keeps command lines and
            // package lists in it). Comments, processing instructions and the DOCTYPE carry nothing used here.
            if let Some(body) = rest.strip_prefix("<![CDATA[") {
                let Some(end) = body.find("]]>") else {
                    self.failed = true;
                    return None;
                };
                self.at += "<![CDATA[".len() + end + "]]>".len();
                if body[..end].trim().is_empty() {
                    continue;
                }
                return Some(Token::Text(Cow::Borrowed(&body[..end])));
            }
            let skip_to = |marker: &str| rest.find(marker).map(|i| i + marker.len());
            let skipped = if rest.starts_with("<!--") {
                skip_to("-->")
            } else if rest.starts_with("<?") {
                skip_to("?>")
            } else if rest.starts_with("<!") {
                // A DOCTYPE may hold an internal subset in brackets; entity declarations are not followed.
                match rest.find('[') {
                    Some(open) if rest[..open].find('>').is_none() => rest.find("]>").map(|i| i + 2),
                    _ => skip_to(">"),
                }
            } else {
                None
            };
            if rest.starts_with("<!") || rest.starts_with("<?") {
                match skipped {
                    Some(n) => {
                        self.at += n;
                        continue;
                    }
                    None => {
                        self.failed = true;
                        return None;
                    }
                }
            }
            let Some(close) = tag_end(rest) else {
                self.failed = true;
                return None;
            };
            let inner = &rest[1..close];
            self.at += close + 1;
            if let Some(name) = inner.strip_prefix('/') {
                return Some(Token::End(name.trim()));
            }
            let (inner, empty) = match inner.strip_suffix('/') {
                Some(i) => (i, true),
                None => (inner, false),
            };
            let name_end = inner.find(|c: char| c.is_whitespace()).unwrap_or(inner.len());
            let (name, attrs) = (&inner[..name_end], &inner[name_end..]);
            if name.is_empty() {
                self.failed = true;
                return None;
            }
            return Some(Token::Start { name, attrs: attributes(attrs), empty });
        }
    }
}

/// The index of the `>` that ends the tag at the start of `rest`, skipping quoted values.
fn tag_end(rest: &str) -> Option<usize> {
    let mut quote = None;
    for (i, b) in rest.bytes().enumerate().skip(1) {
        match (quote, b) {
            (Some(q), b) if b == q => quote = None,
            (Some(_), _) => {}
            (None, b'"' | b'\'') => quote = Some(b),
            (None, b'>') => return Some(i),
            _ => {}
        }
    }
    None
}

fn attributes(mut text: &str) -> Vec<(&str, Cow<'_, str>)> {
    let mut out = Vec::new();
    while out.len() < MAX_ATTRS {
        text = text.trim_start();
        let Some(eq) = text.find('=') else { break };
        let name = text[..eq].trim();
        let value = text[eq + 1..].trim_start();
        let Some(quote) = value.chars().next().filter(|c| *c == '"' || *c == '\'') else { break };
        let value = &value[1..];
        let Some(end) = value.find(quote) else { break };
        out.push((name, decode(&value[..end])));
        text = &value[end + 1..];
    }
    out
}

/// Decodes `&amp; &lt; &gt; &quot; &apos;` and `&#N;` / `&#xN;`. Unknown references are kept as written.
fn decode(text: &str) -> Cow<'_, str> {
    if !text.contains('&') {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let decoded = rest.find(';').filter(|semi| *semi <= 10).and_then(|semi| {
            let name = &rest[1..semi];
            let ch = match name {
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
            }?;
            Some((ch, semi + 1))
        });
        match decoded {
            Some((ch, used)) => {
                out.push(ch);
                rest = &rest[used..];
            }
            None => {
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

    fn names(text: &str) -> Vec<String> {
        tokens(text)
            .map(|t| match t {
                Token::Start { name, attrs, empty } => {
                    format!("<{name} {}{}", attrs.len(), if empty { " /" } else { "" })
                }
                Token::End(name) => format!("</{name}"),
                Token::Text(text) => format!("'{text}'"),
            })
            .collect()
    }

    #[test]
    fn reads_tags_attributes_and_text() {
        let xml = "<?xml version=\"1.0\"?><!DOCTYPE a SYSTEM \"x.dtd\"><!-- c --><a x='1' y=\"&lt;b&gt;\"><b/>t &amp; u<![CDATA[ & raw ]]></a>";
        assert_eq!(names(xml), ["<a 2", "<b 0 /", "'t & u'", "' & raw '", "</a"]);
        let first = tokens(xml).next();
        let Some(Token::Start { attrs, .. }) = first else { panic!("not a start tag") };
        assert_eq!(attrs[1].1, "<b>");
    }

    #[test]
    fn a_greater_than_inside_a_quoted_value_does_not_end_the_tag() {
        assert_eq!(names("<a v=\"x>y\">z</a>"), ["<a 1", "'z'", "</a"]);
    }

    #[test]
    fn broken_input_stops_without_panic() {
        for text in ["<", "<a", "<a b='", "<!--", "<![CDATA[ x", "&", "<>", "<a b=c>", "\u{e9}<\u{e9}"] {
            let mut t = tokens(text);
            while t.next().is_some() {}
        }
        let mut t = tokens("<a");
        assert!(t.next().is_none() && t.failed());
    }

    #[test]
    fn numeric_entities() {
        assert_eq!(decode("&#65;&#x42;&bogus;&#9999999999;"), "AB&bogus;&#9999999999;");
    }
}
