//! `var/adm/sulog`: every `su` attempt. Format: `SU MM/DD HH:MM + tty from-to`, with `+` for a
//! success and `-` for a failure. `su` writes it only when the file exists and `SULOG` in
//! `/etc/default/su` names it. The line has no year, so it is inferred from the file's
//! modification time, as for classic syslog. The terminal is `???` when `su` had none.
//!
//! Verified on illumos against what `su` printed for each attempt (`SU 11/13 01:16 - pts/1
//! alice-root` is a wrong password).

use super::when::yearless;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::time::parse_uint;
use nixcavate_core::{Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "sulog",
    "su attempts and whether they succeeded (Solaris/illumos sulog)",
    Category::Accounts,
    SOLARIS,
    &["var/adm/sulog*", "var/share/adm/sulog*", "var/log/sulog*"],
    parse,
);

#[derive(Serialize)]
struct Attempt<'a> {
    time: Option<Timestamp>,
    success: bool,
    tty: &'a str,
    /// The user who ran `su`.
    from_user: &'a str,
    /// The account `su` was run for.
    to_user: &'a str,
}

impl Record for Attempt<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = if self.success {
            format!("{} su to {} on {}", self.from_user, self.to_user, self.tty)
        } else {
            format!("failed su to {} by {} on {}", self.to_user, self.from_user, self.tty)
        };
        self.time.map(|ts| Event::new(ts, "su", message)).into_iter()
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() {
            return Ok(());
        }
        let mut words = text.split_whitespace();
        let fields = (words.next(), words.next(), words.next(), words.next(), words.next(), words.next());
        let (Some("SU"), Some(date), Some(clock), Some(flag @ ("+" | "-")), Some(tty), Some(users)) = fields else {
            sink.warn(format!("line {}: not an sulog entry", line.number));
            return Ok(());
        };
        // The user names may hold `-`; the first one (from) is what precedes the first `-`.
        let (from_user, to_user) = users.split_once('-').unwrap_or((users, ""));
        let time = (|| {
            let (month, day) = date.split_once('/')?;
            let (hour, minute) = clock.split_once(':')?;
            let num = |t: &str| u32::try_from(parse_uint(t.as_bytes())?).ok();
            yearless(input, num(month)?, num(day)?, num(hour)?, num(minute)?, 0)
        })();
        sink.emit(Loc::Line(line.number), &Attempt { time, success: flag == "+", tty, from_user, to_user })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const NOV_13_2026: i64 = 1_794_535_000; // a little after the last line of the fixture

    /// The fixture is the sulog of a guest where root ran `su alice` (`root-alice`, tty `???`),
    /// alice ran `su root` with the right and then a wrong password, and `su` to a role.
    #[test]
    fn a_real_sulog() {
        let out = run(&ARTIFACT, "var/adm/sulog", &fixture("sulog/sulog"), NOV_13_2026);
        insta::assert_snapshot!(out);
        assert_eq!(out.matches("\"success\":false").count(), 1, "{out}");
        assert!(
            out.contains(r#""time":"2026-11-13T01:16:00Z","time_basis":"#)
                || out.contains(r#""time":"2026-11-13T01:16:00Z""#),
            "{out}"
        );
        assert!(out.contains("failed su to root by alice on pts/1"), "{out}");
    }

    #[test]
    fn the_year_comes_from_the_file_and_a_missing_reference_leaves_no_time() {
        let line = b"SU 12/31 23:59 + pts/1 alice-root\n";
        // Written in January: a December line belongs to the year before.
        let out = run(&ARTIFACT, "var/adm/sulog", line, 1_704_844_800);
        assert!(out.contains("2023-12-31T23:59:00Z"), "{out}");
        let out = run(&ARTIFACT, "var/adm/sulog", line, 0);
        assert!(out.contains(r#""time":null"#) && !out.contains("--- timeline"), "{out}");
    }

    #[test]
    fn odd_lines_are_warnings_and_users_may_hold_dashes() {
        let out = run(
            &ARTIFACT,
            "var/adm/sulog",
            b"garbage\nSU 02/30 25:61 + pts/1 a-b-c\nSU 03/01 01:02 * pts/1 a-b\n\n",
            NOV_13_2026,
        );
        assert_eq!(out.matches("not an sulog entry").count(), 2, "{out}");
        assert!(out.contains(r#""from_user":"a","to_user":"b-c""#) && out.contains(r#""time":null"#), "{out}");
    }

    #[test]
    fn mutated_files_never_panic() {
        super::super::never_panics(&ARTIFACT, "var/adm/sulog", &fixture("sulog/sulog"));
    }
}
