//! sshd configuration keywords that run a program or force one on login: `AuthorizedKeysCommand`
//! (run as root or `AuthorizedKeysCommandUser` to fetch keys at every login) and
//! `ForceCommand`. Other keywords are not listed. Format: sshd_config(5): keywords are case
//! insensitive, the value follows after blanks or one `=`, and a `Match` line limits the
//! lines after it.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "sshd-config",
    "sshd AuthorizedKeysCommand and ForceCommand",
    Category::Persistence,
    ANY_OS,
    &[
        "etc/ssh/sshd_config",
        "etc/ssh/sshd_config.d/*.conf",
        "private/etc/ssh/sshd_config",
        "private/etc/ssh/sshd_config.d/*.conf",
    ],
    parse,
);

#[derive(Serialize)]
struct Setting<'a> {
    /// The keyword, spelled as in the canonical documentation.
    keyword: &'static str,
    value: &'a str,
    /// The criteria of the `Match` block the line is in; empty when it applies globally.
    match_condition: &'a str,
}

impl Record for Setting<'_> {}

const KEYWORDS: [&str; 3] = ["AuthorizedKeysCommand", "AuthorizedKeysCommandUser", "ForceCommand"];

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut condition = String::new();
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            return Ok(());
        }
        let (word, rest) = text.split_once(|c: char| c.is_whitespace() || c == '=').unwrap_or((text, ""));
        let value = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '=').trim();
        if word.eq_ignore_ascii_case("Match") {
            condition = value.to_string();
        } else if let Some(keyword) = KEYWORDS.iter().find(|k| k.eq_ignore_ascii_case(word)) {
            sink.emit(Loc::Line(line.number), &Setting { keyword, value, match_condition: &condition })?;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;

    #[test]
    fn reads_keywords_with_match_blocks_and_odd_spelling() {
        let data = b"Port 22\nauthorizedkeyscommand /usr/local/bin/keys %u\nAuthorizedKeysCommandUser=root\nMatch User sftp\n\tForceCommand internal-sftp\n";
        let out = run(&ARTIFACT, "etc/ssh/sshd_config", data, 0);
        assert_eq!(out.matches("\"keyword\"").count(), 3, "{out}");
        assert!(out.contains(
            "\"keyword\":\"AuthorizedKeysCommand\",\"value\":\"/usr/local/bin/keys %u\",\"match_condition\":\"\""
        ));
        assert!(out.contains("\"value\":\"root\""), "{out}");
        assert!(out.contains("\"value\":\"internal-sftp\",\"match_condition\":\"User sftp\""), "{out}");
    }

    #[test]
    fn empty_and_garbage_inputs_do_not_panic() {
        run(&ARTIFACT, "etc/ssh/sshd_config", b"", 0);
        run(&ARTIFACT, "etc/ssh/sshd_config", b"\xff\0=\nForceCommand\n=\nMatch\n", 0);
    }
}
