//! Legacy run-control scripts: `etc/rc0.d/` ... `etc/rc6.d/`, `etc/rcS.d/` and `etc/init.d/`. A
//! script `etc/rc2.d/S99name` runs at run level 2 with `start`, and `K...` scripts with `stop`;
//! they are hard links to `etc/init.d/name`. SMF starts the services of Solaris 10 and later, so
//! only a few scripts remain, and one that was added is notable. One record per file: its
//! metadata, interpreter and the commands it runs (comments and blank lines left out; the first
//! 100 are kept).
//!
//! Verified on illumos (OmniOS): the stock `S20sysetup`, `S81dodatadm.udaplt`, `S89PRESERVE` and
//! the harness's `S99nxmk` and `S98nxmk3`.

use crate::text::lossy;
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Basis, Error, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "rc-scripts",
    "Legacy rc scripts (rc0.d - rc6.d, rcS.d, init.d)",
    Category::Persistence,
    SOLARIS,
    &[
        "etc/rc0.d/*",
        "etc/rc1.d/*",
        "etc/rc2.d/*",
        "etc/rc3.d/*",
        "etc/rc5.d/*",
        "etc/rc6.d/*",
        "etc/rcS.d/*",
        "etc/init.d/*",
    ],
    parse,
);

#[derive(Serialize)]
struct Script {
    size: u64,
    /// Permission bits in octal, as collected (`100744`).
    mode: String,
    uid: u32,
    gid: u32,
    modified: Option<Timestamp>,
    /// The `#!` line, without the `#!`.
    interpreter: String,
    lines: u64,
    /// The commands, joined by `; `.
    commands: String,
}

impl Record for Script {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    // Every `rc?.d` directory holds a `README` that is text for the administrator, not a script.
    if input.path.ends_with("/README") {
        return Err(Error::skipped("a README, not a script"));
    }
    let text = lossy(input.data);
    let interpreter =
        text.lines().next().and_then(|l| l.strip_prefix("#!")).map(|s| s.trim().to_string()).unwrap_or_default();
    let commands: Vec<&str> =
        text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).take(100).collect();
    sink.emit(
        Loc::None,
        &Script {
            size: input.data.len() as u64,
            mode: format!("{:o}", input.mode),
            uid: input.uid,
            gid: input.gid,
            modified: (input.mtime > 0).then(|| Timestamp::from_secs(input.mtime, Basis::Recorded)),
            interpreter,
            lines: memchr::memchr_iter(b'\n', input.data).count() as u64,
            commands: commands.join("; "),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn real_rc_scripts() {
        insta::assert_snapshot!(
            "added",
            run(&ARTIFACT, "etc/rc2.d/S99nxmk", &fixture("rc-scripts/S99nxmk"), 1_794_532_000)
        );
        insta::assert_snapshot!(
            "stock",
            run(&ARTIFACT, "etc/rc2.d/S20sysetup", &fixture("rc-scripts/S20sysetup"), 1_700_000_000)
        );
        let out = run(&ARTIFACT, "etc/rc2.d/S99nxmk", &fixture("rc-scripts/S99nxmk"), 0);
        assert!(out.contains(r#""interpreter":"/sbin/sh""#) && out.contains("/tmp/.NXMK_RC2/agent &"), "{out}");
    }

    #[test]
    fn binary_and_empty_files_do_not_panic() {
        run(&ARTIFACT, "etc/rc2.d/S01x", b"", 0);
        run(&ARTIFACT, "etc/rc2.d/S01x", b"\xff\xfe\0#!\x80", 0);
        super::super::never_panics(&ARTIFACT, "etc/rc2.d/S99nxmk", &fixture("rc-scripts/S20sysetup"));
    }
}
