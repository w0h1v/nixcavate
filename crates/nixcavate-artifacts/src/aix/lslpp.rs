//! Installed software from `lslpp` output collected by UAC: `lslpp -a -h -c` (the history of each
//! fileset: installs, updates, commits, removals, with a date) and `lslpp -L -c` (what is installed
//! now). The ODM databases behind them (`etc/objrepos/lpp`, `history`, `product`) are binary files
//! whose layout is not read.
//!
//! Field orders (colon-separated) follow Microsoft's Operations Manager agent source, which parses
//! `lslpp -Lcq all` (`Package Name:Fileset:Level:State:PTF Id:Fix State:Type:Description:...`) and
//! `lslpp -hcq all` (`Path:Fileset:Level:PTF Id:Action:Status:Date:Time`, the time printed with
//! `;` because `:` separates fields), and IBM's `ansible-power-aix` `lpp_facts` module for
//! `lslpp -lc` (`Source:Fileset:Level:PTF Id:State:Type:Description:EFIX Locked`). The dates are
//! `MM/DD/YY`. Two independent sources agree on the history and listing layouts; there was no real
//! output to compare, so the fixtures are synthetic. The date has no zone: the host zone is assumed.

use super::clock::{clock, two_digit_year};
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, AIX};
use nixcavate_core::time::secs_from_civil;
use nixcavate_core::{Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "aix-lslpp",
    "AIX filesets: installation history and installed list (lslpp)",
    Category::Software,
    AIX,
    &["../live_response/packages/lslpp_-a_-h_-c.txt", "../live_response/packages/lslpp_-L_-c.txt"],
    parse,
);

/// RPM packages of the AIX Toolbox, from the RPM database the existing reader understands. The
/// database is a Berkeley DB hash file with big-endian pages (that variant is read: see `rpm-db`).
/// The locations are from the Toolbox's documented `dbpath` settings as remembered, **not
/// confirmed against a real AIX file**: nothing is read if the database is elsewhere.
pub const RPM_DB: Artifact = Artifact::new(
    "aix-rpm-db",
    "AIX Toolbox RPM packages",
    Category::Software,
    AIX,
    &[
        "var/opt/freeware/lib/rpm/Packages",
        "var/opt/freeware/lib/rpm/rpmdb.sqlite",
        "opt/freeware/packages/Packages",
        "usr/opt/freeware/packages/Packages",
    ],
    crate::linux::rpm_db::parse,
);

#[derive(Serialize)]
struct Fileset<'a> {
    /// `history` (one row per action) or `installed`.
    kind: &'static str,
    fileset: &'a str,
    level: &'a str,
    /// Where the fileset's database lives (`/usr/lib/objrepos`, `/etc/objrepos`); history only.
    path: Option<&'a str>,
    action: Option<&'a str>,
    status: Option<&'a str>,
    time: Option<Timestamp>,
    /// The State and Fix State columns of the installed list (`C` committed, `A` applied...).
    state: Option<&'a str>,
    fix_state: Option<&'a str>,
    ptf_id: Option<&'a str>,
    description: Option<&'a str>,
}

impl Record for Fileset<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let (Some(time), Some(action)) = (self.time, self.action) else { return None.into_iter() };
        let status = self.status.unwrap_or("");
        let (kind, verb) = match action {
            "APPLY" | "COMMIT" => ("package_installed", "installed"),
            "DEINSTALL" | "REJECT" => ("package_removed", "removed"),
            _ => ("package_command", action),
        };
        Some(Event::new(time, kind, format!("{verb} {} {} ({action} {status})", self.fileset, self.level))).into_iter()
    }
}

/// `MM/DD/YY` and `HH;MM;SS` as wall-clock seconds.
fn history_time(date: &str, time: &str) -> Option<i64> {
    let mut parts = date.split('/');
    let (m, d, y) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || y.len() != 2 {
        return None;
    }
    let (h, mi, s) = clock(time)?;
    secs_from_civil(two_digit_year(y.parse().ok()?), m.parse().ok()?, d.parse().ok()?, h, mi, s)
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let stamp = |wall: i64| input.local_time(wall, 0, Precision::Seconds);
    let mut layout: Option<bool> = None; // true: history
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if text.trim().is_empty() {
            return Ok(());
        }
        if let Some(header) = text.strip_prefix('#') {
            layout = Some(header.contains("Action") && header.contains("Date"));
            return Ok(());
        }
        let fields: Vec<&str> = text.split(':').map(str::trim).collect();
        let history = layout.unwrap_or_else(|| fields.get(6).is_some_and(|d| d.matches('/').count() == 2));
        let get = |i: usize| fields.get(i).copied().filter(|v| !v.is_empty());
        if history {
            if fields.len() < 8 {
                sink.warn(format!("line {}: expected 8 history fields, found {}", line.number, fields.len()));
                return Ok(());
            }
            let time = history_time(fields[6], fields[7]).map(stamp);
            if time.is_none() {
                sink.warn(format!("line {}: date {} {} is not MM/DD/YY HH;MM;SS", line.number, fields[6], fields[7]));
            }
            sink.emit(
                Loc::Line(line.number),
                &Fileset {
                    kind: "history",
                    fileset: fields[1],
                    level: fields[2],
                    path: get(0),
                    ptf_id: get(3),
                    action: get(4),
                    status: get(5),
                    time,
                    state: None,
                    fix_state: None,
                    description: None,
                },
            )
        } else {
            if fields.len() < 8 {
                sink.warn(format!("line {}: expected at least 8 listing fields, found {}", line.number, fields.len()));
                return Ok(());
            }
            sink.emit(
                Loc::Line(line.number),
                &Fileset {
                    kind: "installed",
                    fileset: fields[1],
                    level: fields[2],
                    path: None,
                    ptf_id: get(4),
                    action: None,
                    status: None,
                    time: None,
                    state: get(3),
                    fix_state: get(5),
                    description: get(7),
                },
            )
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;

    #[test]
    fn history_rows_become_package_events() {
        let data = b"#Path:Fileset:Level:PTF Id:Action:Status:Date:Time\n/usr/lib/objrepos:openssh.base.server:7.5.102.1801::COMMIT:COMPLETE:03/10/21:12;55;38\n/usr/lib/objrepos:evil.rte:1.0.0.0::APPLY:COMPLETE:03/11/21:01;02;03\n/etc/objrepos:evil.rte:1.0.0.0::DEINSTALL:COMPLETE:03/12/21:01;02;03\nbad:row\n";
        let out = run(&ARTIFACT, "../live_response/packages/lslpp_-a_-h_-c.txt", data, 0);
        assert!(out.contains("installed evil.rte 1.0.0.0") && out.contains("removed evil.rte"), "{out}");
        assert!(out.contains("2021-03-10T12:55:38Z"), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn installed_listing() {
        let data = b"#Package Name:Fileset:Level:State:PTF Id:Fix State:Type:Description:Destination Dir.:Uninstaller:Message Catalog:Message Set:Message Number:Parent:Automatic:EFIX Locked:Install Path:Build Date\nbos.rte:bos.rte.commands:7.2.5.0:C: : : :Base Operating System Commands: : : : : :0:0:/:1948\n";
        let out = run(&ARTIFACT, "../live_response/packages/lslpp_-L_-c.txt", data, 0);
        assert!(
            out.contains(r#""fileset":"bos.rte.commands","level":"7.2.5.0""#) && out.contains(r#""state":"C""#),
            "{out}"
        );
    }

    /// The Toolbox's database is read by the same reader as Linux's; here a big-endian Berkeley DB
    /// made by `rpm` on s390x stands in for it (no AIX file was available).
    #[test]
    fn the_toolbox_database_path_uses_the_rpm_reader() {
        let data = crate::testing::fixture("rpm-db/Packages-s390x");
        let out = run(&RPM_DB, "var/opt/freeware/lib/rpm/Packages", &data, 0);
        let records = out.lines().filter(|l| l.starts_with('{')).count();
        assert!(records >= 3 && !out.contains("--- failed"), "{records} records");
    }

    #[test]
    fn hostile() {
        for data in
            [&b""[..], b"#\n:::::::\n", b"\xff:\xfe:::::::\n", &[b':'; 5000][..], b"a:b:c:d:e:f:99/99/99:99;99;99\n"]
        {
            let _ = run(&ARTIFACT, "../live_response/packages/lslpp_-a_-h_-c.txt", data, 0);
        }
    }
}
