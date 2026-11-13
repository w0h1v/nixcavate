//! `etc/hosts.equiv`, `etc/shosts.equiv` and `~/.rhosts`, `~/.shosts`: the trust files of the r-commands
//! (`rlogin`, `rsh`) and of host-based ssh. A line is `host [user]`; `+` alone, or `+ +`, trusts
//! every host and user; `-host` denies; `+@netgroup` names a netgroup. Format: hosts.equiv(4).
//! Anyone who can write one of these files can log in without a password.
//!
//! Verified on illumos (OmniOS): the harness's `+ +` entries in both files. Read the same way on
//! Oracle Solaris from the documentation.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "rhosts",
    "r-command trust files (hosts.equiv, .rhosts)",
    Category::Persistence,
    SOLARIS,
    &[
        "etc/hosts.equiv",
        "etc/shosts.equiv",
        "root/.rhosts",
        "root/.shosts",
        "home/*/.rhosts",
        "home/*/.shosts",
        "export/home/*/.rhosts",
        "export/home/*/.shosts",
    ],
    parse,
);

#[derive(Serialize)]
struct Trust<'a> {
    /// The host, host pattern or `+@netgroup`; `+` is every host.
    trusted_host: &'a str,
    /// The user it applies to; empty means the same user name.
    user: &'a str,
    /// `-host` or `-user`: a denial.
    denies: bool,
    /// A bare `+` for the host or the user: trust without limit.
    wildcard: bool,
}

impl Record for Trust<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.split('#').next().unwrap_or_default().trim();
        if text.is_empty() {
            return Ok(());
        }
        let mut words = text.split_whitespace();
        let (Some(host), user) = (words.next(), words.next().unwrap_or_default()) else { return Ok(()) };
        sink.emit(
            Loc::Line(line.number),
            &Trust {
                trusted_host: host,
                user,
                denies: host.starts_with('-') || user.starts_with('-'),
                wildcard: host == "+" || user == "+",
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn real_trust_files() {
        insta::assert_snapshot!("equiv", run(&ARTIFACT, "etc/hosts.equiv", &fixture("rhosts/hosts.equiv"), 0));
        let out = run(&ARTIFACT, "home/alice/.rhosts", &fixture("rhosts/rhosts"), 0);
        assert!(out.contains(r#""trusted_host":"+","user":"+","denies":false,"wildcard":true"#), "{out}");
    }

    #[test]
    fn denials_netgroups_and_names() {
        let out = run(&ARTIFACT, "etc/hosts.equiv", b"-badhost\n+@staff\nhost2 bob\nhost3 -eve # c\n\n", 0);
        assert!(out.contains(r#""trusted_host":"-badhost","user":"","denies":true,"wildcard":false"#), "{out}");
        assert!(
            out.contains(r#""trusted_host":"+@staff""#)
                && out.contains(r#""trusted_host":"host3","user":"-eve","denies":true"#),
            "{out}"
        );
        super::super::never_panics(&ARTIFACT, "etc/hosts.equiv", &fixture("rhosts/hosts.equiv"));
    }
}
