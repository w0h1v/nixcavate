//! `/etc/hosts`: static name to address mappings. Format: hosts(5). Overrides in this file
//! are a classic way to redirect or block a domain.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "hosts",
    "Static host name mappings",
    Category::Network,
    ANY_OS,
    &["etc/hosts", "private/etc/hosts", "etc/inet/hosts"],
    parse,
);

#[derive(Serialize)]
struct Mapping<'a> {
    address: &'a str,
    names: Vec<&'a str>,
}

impl Record for Mapping<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let content = text.split('#').next().unwrap_or_default();
        let mut tokens = content.split_whitespace();
        let Some(address) = tokens.next() else { return Ok(()) };
        let names: Vec<&str> = tokens.collect();
        if names.is_empty() {
            sink.warn(format!("line {}: address {address} has no names", line.number));
            return Ok(());
        }
        sink.emit(Loc::Line(line.number), &Mapping { address, names })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn parses_mappings() {
        insta::assert_snapshot!(run(&ARTIFACT, "etc/hosts", &fixture("hosts/hosts"), 0));
    }

    #[test]
    fn empty_and_garbage_do_not_panic() {
        assert_eq!(run(&ARTIFACT, "etc/hosts", b"", 0), "");
        let junk: Vec<u8> = (0..=255u8).cycle().take(2000).collect();
        run(&ARTIFACT, "etc/hosts", &junk, 0);
    }
}
