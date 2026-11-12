//! Package-manager histories of the RPM family: `yum.log` (yum), `dnf.rpm.log` and the
//! `history.sqlite` transaction database (dnf, libdnf "swdb" schema).

use crate::common::year::utc_without_year;
use crate::sqlite::{open, sql_error};
use crate::text::{for_each_line, lossy, split_once};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::time::{month_from_abbrev, parse_iso8601, parse_uint};
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;

pub const YUM_LOG: Artifact =
    Artifact::new("yum-log", "yum package actions", Category::Software, LINUX, &["var/log/yum.log*"], parse_yum)
        .split_lines();
pub const DNF_LOG: Artifact =
    Artifact::new("dnf-log", "dnf package actions", Category::Software, LINUX, &["var/log/dnf.rpm.log*"], parse_dnf)
        .split_lines();
pub const DNF5_LOG: Artifact = Artifact::new(
    "dnf5-log",
    "dnf5 commands and package actions",
    Category::Software,
    LINUX,
    &["var/log/dnf5.log*"],
    parse_dnf5,
)
.split_lines();
pub const DNF_HISTORY: Artifact = Artifact::new(
    "dnf-history",
    "dnf transaction history",
    Category::Software,
    LINUX,
    &["var/lib/dnf/history.sqlite"],
    parse_history,
)
.companions(&["var/lib/dnf/history.sqlite-wal"]);

/// The timeline event kind for an action word, `None` when it does not change what is installed.
/// dnf's `Upgraded:` line names the OLD package that was replaced (the new one is on the
/// `Upgrade:` line), so it gets no event.
fn event_kind(action: &str) -> Option<&'static str> {
    Some(match action {
        "installed" | "install" => "package_installed",
        "updated" | "upgrade" => "package_upgraded",
        "erased" | "erase" | "remove" | "removed" => "package_removed",
        _ => return None,
    })
}

#[derive(Serialize)]
struct YumEntry<'a> {
    time: Option<Timestamp>,
    time_basis: Option<Basis>,
    action: String,
    /// The full name-epoch:version-release.arch text.
    package: &'a str,
}

impl Record for YumEntry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let kind = event_kind(&self.action);
        let event =
            self.time.zip(kind).map(|(ts, kind)| Event::new(ts, kind, format!("{} {}", self.action, self.package)));
        event.into_iter()
    }
}

/// `Mar 10 01:02:03 Installed: nmap-2:7.70-8.el7.x86_64`
fn parse_yum(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let bytes = line.bytes;
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let fields = (|| {
            let month = month_from_abbrev(bytes)?;
            let day = parse_uint(bytes.get(4..6)?.trim_ascii())?;
            let (h, m, s) =
                (parse_uint(bytes.get(7..9)?)?, parse_uint(bytes.get(10..12)?)?, parse_uint(bytes.get(13..15)?)?);
            let (action, package) = split_once(bytes.get(16..)?, b':')?;
            Some((month, day as u32, h as u32, m as u32, s as u32, action, package.trim_ascii()))
        })();
        let Some((month, day, h, m, s, action, package)) = fields else {
            sink.warn(format!("offset {}: not a yum log line", line.offset));
            return Ok(());
        };
        let time = utc_without_year(month, day, h, m, s, input.mtime, &input.host.tz)
            .map(|secs| Timestamp::from_secs(secs, Basis::InferredYearAssumedZone));
        sink.emit(
            Loc::Offset(line.offset),
            &YumEntry {
                time,
                time_basis: time.map(|t| t.basis),
                action: lossy(action).to_ascii_lowercase(),
                package: &lossy(package),
            },
        )
    })
}

#[derive(Serialize)]
struct DnfEntry<'a> {
    time: Timestamp,
    level: Cow<'a, str>,
    action: String,
    package: Cow<'a, str>,
    message: Cow<'a, str>,
}

impl Record for DnfEntry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let event = event_kind(&self.action)
            .map(|kind| Event::new(self.time, kind, format!("{} {}", self.action, self.package)));
        event.into_iter()
    }
}

/// `2024-03-10T01:02:03+0000 SUBDEBUG Installed: nmap-3:7.92-1.el9.x86_64`. Other lines carry
/// scriptlet output and become records with a `message`. Scriptlet output of several lines
/// has a timestamp on the first only: the others take the time and level of the line before.
fn parse_dnf(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut before: Option<(Timestamp, String)> = None;
    for_each_line(input, |line| {
        let Some((parsed, used)) = parse_iso8601(line.bytes) else {
            if line.bytes.iter().all(u8::is_ascii_whitespace) {
                return Ok(());
            }
            let Some((time, level)) = &before else {
                sink.warn(format!("offset {}: line does not start with a timestamp", line.offset));
                return Ok(());
            };
            let entry = DnfEntry {
                time: *time,
                level: Cow::Borrowed(level),
                action: String::new(),
                package: Cow::Borrowed(""),
                message: lossy(line.bytes.trim_ascii()),
            };
            return sink.emit(Loc::Offset(line.offset), &entry);
        };
        let Some(time) = parsed.recorded() else {
            sink.warn(format!("offset {}: timestamp has no zone", line.offset));
            return Ok(());
        };
        let rest = line.bytes[used..].trim_ascii_start();
        let (level, rest) = split_once(rest, b' ').unwrap_or((rest, b""));
        before = Some((time, lossy(level).into_owned()));
        // A package action is a single word before the colon; anything else is free text.
        let action = split_once(rest, b':')
            .filter(|(word, _)| !word.is_empty() && word.iter().all(u8::is_ascii_alphabetic))
            .filter(|(word, _)| {
                let word = lossy(word).to_ascii_lowercase();
                matches!(
                    word.as_str(),
                    "installed"
                        | "upgrade"
                        | "upgraded"
                        | "erase"
                        | "reinstall"
                        | "reinstalled"
                        | "downgrade"
                        | "downgraded"
                        | "obsoleted"
                        | "obsoleting"
                        | "cleanup"
                        | "verifying"
                )
            });
        let (action, package, message) = match action {
            Some((word, package)) => (lossy(word).to_ascii_lowercase(), lossy(package.trim_ascii()), Cow::Borrowed("")),
            None => (String::new(), Cow::Borrowed(""), lossy(rest)),
        };
        sink.emit(Loc::Offset(line.offset), &DnfEntry { time, level: lossy(level), action, package, message })
    })
}

#[derive(Serialize)]
struct Dnf5Entry<'a> {
    time: Option<Timestamp>,
    pid: Option<u32>,
    level: &'a str,
    /// `installed` or `removed` for a finished package action, otherwise empty.
    action: &'static str,
    package: &'a str,
    message: &'a str,
}

impl Record for Dnf5Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let event = self
            .time
            .zip(event_kind(self.action))
            .map(|(time, kind)| Event::new(time, kind, format!("{} {}", self.action, self.package)));
        event.into_iter()
    }
}

/// `2026-03-10T01:02:05+0000 [199] INFO RPM callback install stop "zip-0:3.0-46.fc45.x86_64" ...`.
/// dnf5 logs each package twice (`start`, `stop`): the `stop` line is the action. An upgrade is
/// an install of the new package and an uninstall of the old one. A line that does not start
/// with a timestamp (scriptlet output) is kept as a message with no time.
fn parse_dnf5(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        if line.bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let text = lossy(line.bytes);
        let stamp = parse_iso8601(line.bytes).and_then(|(parsed, used)| Some((parsed.recorded()?, used)));
        let (time, rest) = match stamp {
            Some((time, used)) => (Some(time), text.get(used..).unwrap_or_default().trim_start()),
            None => (None, &*text),
        };
        // `[pid] LEVEL message`, only after a timestamp.
        let fields = time.and_then(|_| {
            let (pid, rest) = rest.strip_prefix('[')?.split_once("] ")?;
            let (level, message) = rest.split_once(' ').unwrap_or((rest, ""));
            Some((pid.parse().ok(), level, message))
        });
        let (pid, level, message) = fields.unwrap_or((None, "", rest));
        let finished = |verb: &str| {
            let quoted = message.strip_prefix("RPM callback ")?.strip_prefix(verb)?.strip_prefix(" stop \"")?;
            quoted.split_once('"').map(|(package, _)| package)
        };
        let (action, package) = match (finished("install"), finished("uninstall")) {
            (Some(package), _) => ("installed", package),
            (_, Some(package)) => ("removed", package),
            _ => ("", ""),
        };
        sink.emit(Loc::Offset(line.offset), &Dnf5Entry { time, pid, level, action, package, message })
    })
}

#[derive(Serialize)]
struct Item {
    time: Timestamp,
    end_time: Option<Timestamp>,
    transaction_id: i64,
    /// The login uid that ran dnf; -1 when the session had none.
    uid: i64,
    command: String,
    action: &'static str,
    package: String,
    epoch: i64,
    version: String,
    release: String,
    architecture: String,
    repository: String,
}

impl Record for Item {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let kind = match self.action {
            "install" => "package_installed",
            "upgrade" => "package_upgraded",
            "remove" => "package_removed",
            _ => "package_changed",
        };
        let message = format!(
            "{} {}-{}-{}.{} ({})",
            self.action, self.package, self.version, self.release, self.architecture, self.command
        );
        Some(Event::new(self.time, kind, message)).into_iter()
    }
}

/// libdnf `TransactionItemAction`, checked against a rockylinux:9 history database.
fn action_name(code: i64) -> &'static str {
    match code {
        1 => "install",
        2 => "downgrade",
        3 => "downgraded",
        4 => "obsolete",
        5 => "obsoleted",
        6 => "upgrade",
        7 => "upgraded",
        8 => "remove",
        9 => "reinstall",
        10 => "reinstalled",
        11 => "reason_change",
        _ => "unknown",
    }
}

fn parse_history(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open(input)?;
    if !["trans", "trans_item", "rpm"].iter().all(|table| db.has_table(table)) {
        return Err(Error::skipped("not a dnf history database"));
    }
    // `rpm` holds package identities; group and environment items have no row there and are left out.
    let mut statement = db
        .conn
        .prepare(
            "SELECT t.id, t.dt_begin, t.dt_end, t.user_id, t.cmdline, i.action, r.name, r.epoch, r.version, r.release, r.arch, repo.repoid \
             FROM trans_item i JOIN trans t ON t.id = i.trans_id JOIN rpm r ON r.item_id = i.item_id \
             LEFT JOIN repo ON repo.id = i.repo_id ORDER BY t.id, i.id",
        )
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let text = |at: usize| row.get::<_, Option<String>>(at).ok().flatten().unwrap_or_default();
        let number = |at: usize| row.get::<_, Option<i64>>(at).ok().flatten();
        let Some(begin) = number(1) else {
            sink.warn("transaction without a start time".to_string());
            continue;
        };
        sink.emit(
            Loc::None,
            &Item {
                time: Timestamp::from_secs(begin, Basis::Recorded),
                end_time: number(2).map(|secs| Timestamp::from_secs(secs, Basis::Recorded)),
                transaction_id: number(0).unwrap_or(0),
                uid: number(3).unwrap_or(-1),
                command: text(4),
                action: action_name(number(5).unwrap_or(0)),
                package: text(6),
                epoch: number(7).unwrap_or(0),
                version: text(8),
                release: text(9),
                architecture: text(10),
                repository: text(11),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const MAR_10_2024_EVENING: i64 = 1_710_100_000;

    #[test]
    fn parses_yum_log() {
        insta::assert_snapshot!(run(&YUM_LOG, "var/log/yum.log", &fixture("yum-log/yum.log"), MAR_10_2024_EVENING));
    }

    #[test]
    fn yum_log_without_a_reference_time_has_no_time() {
        let out = run(&YUM_LOG, "var/log/yum.log", b"Mar 10 01:02:03 Installed: nmap-2:7.70-8.el7.x86_64\n", 0);
        assert!(out.contains("\"time\":null,\"time_basis\":null") && !out.contains("timeline"), "{out}");
    }

    #[test]
    fn parses_dnf_log_from_a_real_host() {
        insta::assert_snapshot!(run(&DNF_LOG, "var/log/dnf.rpm.log", &fixture("dnf-log/dnf.rpm.log"), 0));
    }

    #[test]
    fn dnf_log_keeps_other_lines_as_messages() {
        insta::assert_snapshot!(run(&DNF_LOG, "var/log/dnf.rpm.log", &fixture("dnf-log/scriptlets.log"), 0));
    }

    #[test]
    fn dnf_scriptlet_output_continues_the_line_before_it() {
        let log = "2024-03-10T01:02:03+0000 INFO Created symlink /etc/a.service \u{2192} /usr/lib/a.service.\n\
                   Created symlink /etc/b.socket \u{2192} /usr/lib/b.socket.\n\n\
                   2024-03-10T01:02:04+0000 SUBDEBUG Installed: nmap-3:7.92-1.el9.x86_64\n";
        let text = run(&DNF_LOG, "var/log/dnf.rpm.log", log.as_bytes(), 0);
        assert!(!text.contains("warning"), "{text}");
        let second = r#""time":"2024-03-10T01:02:03Z","level":"INFO","action":"","package":"","message":"Created symlink /etc/b.socket"#;
        assert!(text.contains(second), "{text}");
        // With no line before it, there is no time to give the text.
        let text = run(&DNF_LOG, "var/log/dnf.rpm.log", b"stray output\n", 0);
        assert!(text.contains("line does not start with a timestamp"), "{text}");
    }

    #[test]
    fn dnf5_log_records_the_command_and_the_package_changes() {
        let log = concat!(
            "2026-03-10T01:02:03+0000 [199] INFO --- DNF5 launched with arguments: \"dnf -y install zip\" ---\n",
            "2026-03-10T01:02:04+0000 [199] DEBUG [librepo] lr_download: Target: Packages/z/zip-3.0-46.fc45.x86_64.rpm (-)\n",
            "2026-03-10T01:02:05+0000 [199] INFO RPM callback install start \"zip-0:3.0-46.fc45.x86_64\" total 484756\n",
            "2026-03-10T01:02:05+0000 [199] INFO RPM callback install stop \"zip-0:3.0-46.fc45.x86_64\" amount 484756 total 484756\n",
            "2026-03-10T01:02:09+0000 [216] INFO RPM callback uninstall stop \"zip-0:3.0-46.fc45.x86_64\" amount 5 total 5\n",
            "not a log line\n",
        );
        let text = run(&DNF5_LOG, "var/log/dnf5.log", log.as_bytes(), 0);
        assert_eq!(text.lines().filter(|l| l.starts_with('{')).count(), 6, "{text}");
        assert!(
            text.contains(r#""pid":199,"level":"INFO","action":"installed","package":"zip-0:3.0-46.fc45.x86_64""#),
            "{text}"
        );
        assert!(text.contains("package_installed,installed zip-0:3.0-46.fc45.x86_64"), "{text}");
        assert!(text.contains("package_removed,removed zip-0:3.0-46.fc45.x86_64"), "{text}");
        assert_eq!(text.matches(",package_").count(), 2, "start lines and downloads are not events: {text}");
        assert!(text.contains(r#""message":"not a log line""#) && !text.contains("warning"), "{text}");
    }

    #[test]
    fn parses_dnf_history() {
        insta::assert_snapshot!(run(
            &DNF_HISTORY,
            "var/lib/dnf/history.sqlite",
            &fixture("dnf-history/history.sqlite"),
            0
        ));
    }

    #[test]
    fn history_rejects_other_files() {
        let path = "var/lib/dnf/history.sqlite";
        assert!(run(&DNF_HISTORY, path, b"", 0).contains("skipped: not an SQLite database"));
        assert!(run(&DNF_HISTORY, path, b"plain text", 0).contains("skipped: not an SQLite database"));
        let rpmdb = fixture("rpm-db/rpmdb.sqlite");
        assert!(run(&DNF_HISTORY, path, &rpmdb, 0).contains("skipped: not a dnf history database"));
    }

    #[test]
    fn dnf_upgraded_line_names_the_old_package_and_has_no_event() {
        let data = b"2026-11-11T19:37:38+0000 SUBDEBUG Upgrade: sqlite-libs-3.40.0-1.el9.aarch64\n2026-11-11T19:37:39+0000 SUBDEBUG Upgraded: sqlite-libs-3.34.1-6.el9_1.aarch64\n";
        let out = run(&DNF_LOG, "var/log/dnf.rpm.log", data, 0);
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 2, "{out}");
        let timeline = out.split("--- timeline ---\n").nth(1).unwrap();
        assert!(timeline.contains("3.40.0") && !timeline.contains("3.34.1"), "{timeline}");
    }

    #[test]
    fn empty_logs_produce_nothing() {
        assert_eq!(run(&YUM_LOG, "var/log/yum.log", b"", 1), "");
        assert_eq!(run(&DNF_LOG, "var/log/dnf.rpm.log", b"", 0), "");
    }
}
