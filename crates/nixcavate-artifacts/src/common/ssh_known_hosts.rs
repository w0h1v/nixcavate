//! SSH `known_hosts` files: the hosts a user (or the system) has connected to or trusts.
//! Format: sshd(8), "SSH_KNOWN_HOSTS FILE FORMAT". Hashed entries hide the host name, but the
//! key fingerprint still identifies the server.

use super::home::user_from_path;
use super::ssh_key::fingerprint;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "ssh-known-hosts",
    "SSH known host keys",
    Category::Network,
    ANY_OS,
    &[
        "home/*/.ssh/known_hosts*",
        "root/.ssh/known_hosts*",
        "Users/*/.ssh/known_hosts*",
        "private/var/root/.ssh/known_hosts*",
        "var/root/.ssh/known_hosts*",
        "export/home/*/.ssh/known_hosts*",
        "etc/ssh/ssh_known_hosts*",
        "private/etc/ssh/ssh_known_hosts*",
    ],
    parse,
);

#[derive(Serialize)]
struct KnownHost<'a> {
    user: &'a str,
    /// `@cert-authority`, `@revoked` or empty.
    marker: &'a str,
    /// Host patterns; a hashed entry is the single `|1|salt|hash` token.
    hosts: Vec<&'a str>,
    hashed: bool,
    key_type: &'a str,
    /// OpenSSH style `SHA256:` fingerprint, as printed by `ssh-keygen -l`.
    fingerprint: Option<String>,
    comment: &'a str,
}

impl Record for KnownHost<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let user = user_from_path(input.path);
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let mut rest = text.trim_start();
        if rest.is_empty() || rest.starts_with('#') {
            return Ok(());
        }
        let mut next = || {
            let (token, tail) = rest.split_once([' ', '\t']).unwrap_or((rest, ""));
            rest = tail.trim_start();
            token
        };
        let mut hosts = next();
        let marker = if hosts.starts_with('@') {
            let marker = hosts;
            hosts = next();
            marker
        } else {
            ""
        };
        let (key_type, key) = (next(), next());
        if hosts.is_empty() || key_type.is_empty() || key.is_empty() {
            sink.warn(format!("line {}: expected hosts, key type and key", line.number));
            return Ok(());
        }
        let fingerprint = fingerprint(key_type, key);
        if fingerprint.is_none() {
            sink.warn(format!("line {}: key does not decode to a {key_type} key", line.number));
        }
        let hashed = hosts.starts_with("|1|");
        let hosts = if hashed { vec![hosts] } else { hosts.split(',').collect() };
        sink.emit(
            Loc::Line(line.number),
            &KnownHost { user, marker, hosts, hashed, key_type, fingerprint, comment: rest.trim_end() },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn var_root_home_is_covered() {
        use nixcavate_source::glob::Pattern;
        assert!(ARTIFACT.paths.iter().any(|p| Pattern::new(p).matches("var/root/.ssh/known_hosts")));
    }

    #[test]
    fn parses_known_hosts() {
        insta::assert_snapshot!(run(
            &ARTIFACT,
            "home/alice/.ssh/known_hosts",
            &fixture("ssh-known-hosts/known_hosts"),
            0
        ));
    }

    /// Expected values were printed by `ssh-keygen -lf` (OpenSSH 9.2, debian:12) for the same
    /// keys: ed25519, 2048-bit rsa and ecdsa-nistp256.
    #[test]
    fn fingerprints_match_ssh_keygen() {
        let out = run(&ARTIFACT, "root/.ssh/known_hosts", &fixture("ssh-known-hosts/known_hosts"), 0);
        for fp in [
            "SHA256:WsaXduMJ/3PLy1dRklTpm1DVqhM42imksgErYqhEfAY",
            "SHA256:x9cEHz/kAEOlWO4p0d/HWwfo/0fE4A15EdZABerl8fw",
            "SHA256:dQODpTvemPcE0Dc+giGWgtn++0K16KBKO7VWaxfrbl0",
        ] {
            assert!(out.contains(fp), "missing {fp}");
        }
    }

    #[test]
    fn empty_and_garbage_do_not_panic() {
        assert_eq!(run(&ARTIFACT, "etc/ssh/ssh_known_hosts", b"", 0), "");
        let junk: Vec<u8> = (0..=255u8).cycle().take(2000).collect();
        run(&ARTIFACT, "etc/ssh/ssh_known_hosts", &junk, 0);
    }
}
