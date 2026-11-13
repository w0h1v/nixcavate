//! A line reader for INI files and the flat subset of TOML (`[section]`, `[[table]]`,
//! `key = value`), plus `key value` lines for formats such as OpenVPN's. Used by the credential,
//! VPN and remote-access artifacts, which need a handful of keys from files whose full grammars
//! they never touch. TOML arrays that continue over lines, inline tables and multi-line strings
//! are not understood: their continuation lines are skipped and their first line is kept as the
//! value text.

/// Most pairs one file may give; the rest are dropped.
pub const MAX_PAIRS: usize = 100_000;

pub struct Pair<'a> {
    /// The enclosing `[section]` or `[[table]]` name; empty before the first one.
    pub section: &'a str,
    /// 1-based occurrence of that section name (for repeated `[[proxies]]` tables).
    pub index: u32,
    pub key: &'a str,
    /// Without surrounding quotes and, for unquoted values, without a trailing ` #` comment.
    pub value: &'a str,
}

/// With `spaces`, a line with no `=` is split at its first run of whitespace.
pub fn pairs(text: &str, spaces: bool) -> Vec<Pair<'_>> {
    let mut out = Vec::new();
    let (mut section, mut index) = ("", 0u32);
    let mut seen: Vec<(&str, u32)> = Vec::new();
    let mut block: Option<&str> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(end) = block {
            if line.starts_with("</") && line.contains(end) {
                block = None;
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        // OpenVPN inline files: <key> ... </key>.
        if line.starts_with('<') && !line.starts_with("</") && line.ends_with('>') && !line.contains(' ') {
            block = Some(line.trim_matches(['<', '>']));
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.trim_end().strip_suffix(']')) {
            section = name.trim_matches(['[', ']']).trim();
            let count = seen.iter().find(|(s, _)| *s == section).map_or(0, |(_, c)| *c) + 1;
            seen.retain(|(s, _)| *s != section);
            seen.push((section, count));
            index = count;
            continue;
        }
        let split = match line.find('=') {
            Some(at) => line.get(..at).zip(line.get(at + 1..)),
            None if spaces => line.split_once(char::is_whitespace).or(Some((line, ""))),
            None => None,
        };
        let Some((key, value)) = split else { continue };
        let value = value.trim();
        let value = if let Some(quoted) = value.strip_prefix('"').and_then(|v| v.split('"').next()) {
            quoted
        } else if let Some(quoted) = value.strip_prefix('\'').and_then(|v| v.split('\'').next()) {
            quoted
        } else {
            value.split(" #").next().unwrap_or(value).trim()
        };
        if out.len() < MAX_PAIRS {
            out.push(Pair { section, index, key: key.trim(), value });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_tables_quotes_and_inline_blocks() {
        let text = "# c\n[Interface]\nAddress = 10.0.0.2/24\n[[proxies]]\nname = \"ssh\" # why\n[[proxies]]\nname = web\nremote 10.1.1.1 1194\n<key>\nsecret = x\n</key>\nlast=1\n";
        let p = pairs(text, true);
        let got: Vec<_> = p.iter().map(|p| (p.section, p.index, p.key, p.value)).collect();
        assert_eq!(
            got,
            [
                ("Interface", 1, "Address", "10.0.0.2/24"),
                ("proxies", 1, "name", "ssh"),
                ("proxies", 2, "name", "web"),
                ("proxies", 2, "remote", "10.1.1.1 1194"),
                ("proxies", 2, "last", "1"),
            ]
        );
        assert!(pairs("remote x 1", false).is_empty());
        let bare = pairs("client\nauth-user-pass /etc/p", true);
        assert_eq!((bare[0].key, bare[0].value, bare[1].value), ("client", "", "/etc/p"));
    }
}
