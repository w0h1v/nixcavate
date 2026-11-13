//! AIX stanza files: `etc/security/user`, `passwd`, `group`, `lastlog`, `limits`, `login.cfg`,
//! `environ`, `audit/config`, `smitacl.*`. One `name:` line at the left margin, then indented
//! `attribute = value` lines; a line starting with `*` is a comment.
//!
//! Sources: two public examples of `/etc/security/lastlog` (a Sys Admin magazine article on the
//! `lsuser`/lastlog tools, and an administrator's blog post with real output) show the shape;
//! the L0phtCrack AIX importer's stanza reader and SaltStack's `aix_shadow` module (which edits
//! `etc/security/lastlog` with `chsec`) agree on the header and attribute lines, and the importer
//! also skips `#` comments and treats a blank line as nothing more than a gap. IBM's "Files
//! Reference" pages were not reachable from here. This reader is as permissive as the importer:
//! a blank line does not end a stanza, and quotes around a value are dropped.

use crate::text::{decompressed, lossy};
use crate::Input;
use nixcavate_core::{Error, Result, Sink};
use std::collections::BTreeMap;

/// The most attributes kept per stanza; a hostile file cannot grow one record without bound.
const MAX_ATTRIBUTES: usize = 512;
/// Larger files are read as far as this and the rest is named in a warning.
const MAX_BYTES: usize = 64 << 20;

pub struct Stanza<'a> {
    pub name: &'a str,
    /// The line of the `name:` header, 1-based.
    pub line: u64,
    pub attributes: BTreeMap<&'a str, &'a str>,
}

impl Stanza<'_> {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).copied()
    }
}

/// Splits `text` into stanzas and calls `f` for each. Lines that fit no rule are one warning.
pub fn for_each_stanza<'a>(
    text: &'a str,
    sink: &mut Sink,
    mut f: impl FnMut(&mut Sink, Stanza<'a>) -> Result<()>,
) -> Result<()> {
    let mut current: Option<Stanza<'a>> = None;
    let (mut stray, mut first_stray, mut dropped) = (0u64, 0u64, 0u64);
    for (index, raw) in text.lines().enumerate() {
        let number = index as u64 + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('*') || line.starts_with('#') {
            continue;
        }
        let colon = line.find(':');
        let equals = line.find('=');
        if let Some(colon) = colon.filter(|c| equals.is_none_or(|e| *c < e) && !raw.starts_with([' ', '\t'])) {
            if let Some(done) = current.take() {
                f(sink, done)?;
            }
            current = Some(Stanza { name: line[..colon].trim(), line: number, attributes: BTreeMap::new() });
        } else if let (Some(equals), Some(stanza)) = (equals, current.as_mut()) {
            let key = line[..equals].trim();
            let value = line[equals + 1..].trim();
            let value = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value);
            if stanza.attributes.len() < MAX_ATTRIBUTES || stanza.attributes.contains_key(key) {
                stanza.attributes.insert(key, value);
            } else {
                dropped += 1;
            }
        } else {
            stray += 1;
            first_stray = if first_stray == 0 { number } else { first_stray };
        }
    }
    if let Some(done) = current.take() {
        f(sink, done)?;
    }
    if stray > 0 {
        sink.warn(format!(
            "{stray} lines are neither a stanza header nor an attribute (the first is line {first_stray})"
        ));
    }
    if dropped > 0 {
        sink.warn(format!("{dropped} attributes beyond {MAX_ATTRIBUTES} in one stanza were not read"));
    }
    Ok(())
}

/// Reads a stanza artifact's input as text.
pub fn read<'a>(input: &'a Input, sink: &mut Sink) -> Result<std::borrow::Cow<'a, str>> {
    let data = decompressed(input.data)?;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    let data = match data {
        std::borrow::Cow::Borrowed(bytes) => {
            if bytes.len() > MAX_BYTES {
                sink.warn(format!("only the first {} MiB were read", MAX_BYTES >> 20));
            }
            lossy(&bytes[..bytes.len().min(MAX_BYTES)])
        }
        std::borrow::Cow::Owned(mut bytes) => {
            if bytes.len() > MAX_BYTES {
                sink.warn(format!("only the first {} MiB were read", MAX_BYTES >> 20));
                bytes.truncate(MAX_BYTES);
            }
            std::borrow::Cow::Owned(String::from_utf8_lossy(&bytes).into_owned())
        }
    };
    Ok(data)
}
