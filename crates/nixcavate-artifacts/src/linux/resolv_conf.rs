//! `/etc/resolv.conf`: DNS resolver settings. Format: resolv.conf(5). A changed nameserver is
//! a common sign of DNS hijacking.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, UNIX};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact =
    Artifact::new("resolv-conf", "DNS resolver configuration", Category::Network, UNIX, &["etc/resolv.conf"], parse);

#[derive(Serialize)]
struct Setting<'a> {
    keyword: &'a str,
    value: &'a str,
}

impl Record for Setting<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let trimmed = text.trim();
        // The resolver accepts both `#` and `;` at the start of a line as comments.
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            return Ok(());
        }
        let (keyword, value) = match trimmed.split_once(char::is_whitespace) {
            Some((keyword, value)) => (keyword, value.trim()),
            None => (trimmed, ""),
        };
        sink.emit(Loc::Line(line.number), &Setting { keyword, value })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn parses_settings() {
        insta::assert_snapshot!(run(&ARTIFACT, "etc/resolv.conf", &fixture("resolv-conf/resolv.conf"), 0));
    }

    #[test]
    fn empty_and_garbage_do_not_panic() {
        assert_eq!(run(&ARTIFACT, "etc/resolv.conf", b"", 0), "");
        let junk: Vec<u8> = (0..=255u8).cycle().take(2000).collect();
        run(&ARTIFACT, "etc/resolv.conf", &junk, 0);
    }
}
