//! `var/adm/sulog`: every `su` attempt, one line each: `SU 03/10 01:02 + pts/1 alice-root`
//! (`+` success, `-` failure, the terminal, then `from-to`). There is no year, so it is inferred
//! from the file's modification time, and the time is wall-clock in the host zone.
//!
//! Source: the SVR4 `sulog` format as the illumos manual page `sulog(5)` documents it, with the
//! same example lines. IBM's own description of AIX's file could not be fetched, and no real AIX
//! file was available: **synthetic only**, from a format two System V descendants share. A line
//! that does not fit is a warning, never a guess.

use crate::common::year::utc_without_year;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, AIX};
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact =
    Artifact::new("aix-sulog", "AIX su attempts", Category::Accounts, AIX, &["var/adm/sulog*"], parse);

#[derive(Serialize)]
struct Attempt<'a> {
    time: Option<Timestamp>,
    success: bool,
    tty: &'a str,
    /// The text as written (`alice-root`). The split below is at the last `-`, so a target user
    /// whose name contains a dash is split wrongly.
    users: &'a str,
    from_user: &'a str,
    to_user: &'a str,
}

impl Record for Attempt<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let (kind, verb) = if self.success { ("su", "switched to") } else { ("failed_su", "failed to switch to") };
        self.time
            .map(|ts| Event::new(ts, kind, format!("{} {verb} {} on {}", self.from_user, self.to_user, self.tty)))
            .into_iter()
    }
}

fn two_digits(text: &str) -> Option<u32> {
    (text.len() == 2 && text.bytes().all(|b| b.is_ascii_digit())).then(|| text.parse().ok()).flatten()
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() {
            return Ok(());
        }
        let words: Vec<&str> = text.split_whitespace().collect();
        let parsed = (|| {
            let [su, date, clock, sign, tty, users] = words[..] else { return None };
            let (month, day) = date.split_once('/')?;
            let (hour, minute) = clock.split_once(':')?;
            let (month, day, hour, minute) =
                (two_digits(month)?, two_digits(day)?, two_digits(hour)?, two_digits(minute)?);
            let success = match sign {
                "+" => true,
                "-" => false,
                _ => return None,
            };
            (su == "SU" && (1..=12).contains(&month) && hour < 24 && minute < 60)
                .then_some((month, day, hour, minute, success, tty, users))
        })();
        let Some((month, day, hour, minute, success, tty, users)) = parsed else {
            sink.warn(format!("line {}: not an sulog line", line.number));
            return Ok(());
        };
        let time = utc_without_year(month, day, hour, minute, 0, input.mtime, &input.host.tz)
            .map(|utc| Timestamp::from_secs(utc, Basis::InferredYearAssumedZone));
        let (from_user, to_user) = users.rsplit_once('-').unwrap_or((users, ""));
        sink.emit(Loc::Line(line.number), &Attempt { time, success, tty, users, from_user, to_user })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;

    const MAR_11_2024: i64 = 1_710_115_200;

    #[test]
    fn successes_and_failures() {
        let data = b"SU 03/10 01:02 + pts/1 alice-root\nSU 03/10 01:05 - pts/2 bob-root\nSU 12/31 23:59 + pts/1 carol-db-admin\n";
        let out = run(&ARTIFACT, "var/adm/sulog", data, MAR_11_2024);
        assert!(
            out.contains("alice switched to root on pts/1") && out.contains("bob failed to switch to root"),
            "{out}"
        );
        assert!(out.contains("2023-12-31T23:59:00Z"), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn bad_lines_are_warnings_and_no_mtime_means_no_time() {
        let out = run(
            &ARTIFACT,
            "var/adm/sulog",
            b"SU 13/10 01:02 + pts/1 a-b\nnonsense\nSU 03/10 01:02 ? pts/1 a-b\nSU 03/10 01:02 + pts/1 a-b\n",
            0,
        );
        assert_eq!(out.matches("not an sulog line").count(), 3, "{out}");
        assert!(out.contains("\"time\":null"), "{out}");
    }

    #[test]
    fn hostile() {
        for data in [&b""[..], b"\xff\xfe\0", b"SU 99/99 99:99 + x y-z\n", &[b'S'; 5000][..]] {
            let _ = run(&ARTIFACT, "var/adm/sulog", data, MAR_11_2024);
        }
    }
}
