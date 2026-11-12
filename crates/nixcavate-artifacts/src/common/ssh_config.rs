//! OpenSSH client and server configuration, one record per directive. Format: ssh_config(5)
//! and sshd_config(5). Useful for spotting `ProxyCommand`, `PermitRootLogin`, `AuthorizedKeysFile`
//! and `ForceCommand` changes.

use super::home::user_from_path;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "ssh-config",
    "SSH client and server configuration",
    Category::Network,
    ANY_OS,
    &[
        "home/*/.ssh/config",
        "root/.ssh/config",
        "Users/*/.ssh/config",
        "etc/ssh/ssh_config",
        "etc/ssh/ssh_config.d/*",
        "private/etc/ssh/ssh_config",
        "etc/ssh/sshd_config",
        "etc/ssh/sshd_config.d/*",
        "private/etc/ssh/sshd_config",
    ],
    parse,
);

#[derive(Serialize)]
struct Directive<'a> {
    user: &'a str,
    /// `client` or `server`.
    config_kind: &'static str,
    /// The `Host` or `Match` line the directive falls under; empty at top level. The `Host`
    /// and `Match` lines themselves are top-level directives.
    block: &'a str,
    keyword: &'a str,
    value: &'a str,
}

impl Record for Directive<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let user = user_from_path(input.path);
    let config_kind = if input.path.contains("sshd_config") { "server" } else { "client" };
    // The block text must outlive each line, so it is kept as an owned copy.
    let mut block = String::new();
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let trimmed = text.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Ok(());
        }
        // `Keyword value`, `Keyword=value` or `Keyword = value`.
        let split = trimmed.find(|c: char| c.is_whitespace() || c == '=').unwrap_or(trimmed.len());
        let (keyword, rest) = trimmed.split_at(split);
        let value = rest.trim_start().trim_start_matches('=').trim();
        let value = match value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            Some(inner) if !inner.contains('"') => inner,
            _ => value,
        };
        let opens_block = keyword.eq_ignore_ascii_case("host") || keyword.eq_ignore_ascii_case("match");
        if opens_block {
            let record = Directive { user, config_kind, block: "", keyword, value };
            sink.emit(Loc::Line(line.number), &record)?;
            block.clear();
            block.push_str(trimmed);
            return Ok(());
        }
        sink.emit(Loc::Line(line.number), &Directive { user, config_kind, block: &block, keyword, value })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn parses_client_config() {
        insta::assert_snapshot!(run(&ARTIFACT, "home/alice/.ssh/config", &fixture("ssh-config/ssh_config"), 0));
    }

    #[test]
    fn parses_server_config() {
        insta::assert_snapshot!(run(&ARTIFACT, "etc/ssh/sshd_config", &fixture("ssh-config/sshd_config"), 0));
    }

    #[test]
    fn empty_and_garbage_do_not_panic() {
        assert_eq!(run(&ARTIFACT, "etc/ssh/ssh_config", b"", 0), "");
        let junk: Vec<u8> = (0..=255u8).cycle().take(2000).collect();
        run(&ARTIFACT, "etc/ssh/sshd_config", &junk, 0);
    }
}
