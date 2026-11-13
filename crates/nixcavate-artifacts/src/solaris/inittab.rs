//! `etc/inittab`: what `init` starts. Format: inittab(5), `id:rstate:action:process`. Solaris
//! 10 and later keep only the SMF bootstrap lines there; everything else is started by SMF, so
//! an added `respawn`, `once` or `sysinit` line is unusual. The `process` field may hold `:`.
//!
//! Verified on illumos (OmniOS): the stock lines, and the harness's added `once` entry, which
//! `init` ran at the next boot and which left an `INIT_PROCESS` record (id `nx`) in `wtmpx`.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "inittab",
    "init entries (Solaris/illumos inittab)",
    Category::Persistence,
    SOLARIS,
    &["etc/inittab"],
    parse,
);

#[derive(Serialize)]
struct Entry<'a> {
    id: &'a str,
    run_levels: &'a str,
    action: &'a str,
    command: &'a str,
}

impl Record for Entry<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            return Ok(());
        }
        let mut fields = text.splitn(4, ':');
        let (Some(id), Some(run_levels), Some(action), Some(command)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            sink.warn(format!("line {}: expected id:rstate:action:process", line.number));
            return Ok(());
        };
        sink.emit(Loc::Line(line.number), &Entry { id, run_levels, action, command: command.trim() })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn a_real_inittab_with_an_added_entry() {
        let out = run(&ARTIFACT, "etc/inittab", &fixture("inittab/inittab"), 0);
        insta::assert_snapshot!(out);
        assert!(out.contains(r#""id":"nx","run_levels":"3","action":"once","command":"/tmp/.NXMK_INITTAB/agent >/dev/null 2>&1 # NXMK_INITTAB""#), "{out}");
        assert!(out.contains(r#""id":"smf","run_levels":"","action":"sysinit""#), "{out}");
    }

    #[test]
    fn the_process_field_may_hold_colons_and_short_lines_warn() {
        let out = run(&ARTIFACT, "etc/inittab", b"is:3:initdefault:\nx:2:wait:/bin/sh -c 'a:b'\nbad\n", 0);
        assert!(
            out.contains(r#""command":"/bin/sh -c 'a:b'""#) && out.contains("expected id:rstate:action:process"),
            "{out}"
        );
        super::super::never_panics(&ARTIFACT, "etc/inittab", &fixture("inittab/inittab"));
    }
}
