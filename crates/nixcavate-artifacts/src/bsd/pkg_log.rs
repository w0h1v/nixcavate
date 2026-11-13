//! Package events that FreeBSD's `pkg(8)` writes to syslog (`/var/log/messages`):
//! `pkg[1084]: zip-3.0_6 deinstalled`. Only these lines become records; the `syslog`
//! artifact has every line. Header layouts: `common::syslog`.

use super::pkg_db::split_name_version;
use crate::common::syslog::for_each_header;
use crate::{Artifact, Category, Input, FREEBSD};
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "pkg-log",
    "FreeBSD pkg install and remove events (syslog)",
    Category::Software,
    FREEBSD,
    &["var/log/messages*"],
    parse,
)
.split_lines();

#[derive(Serialize)]
struct Entry<'a> {
    time: Option<Timestamp>,
    time_basis: Option<Basis>,
    /// `installed`, `deinstalled`, `reinstalled`, `upgraded` or `downgraded`.
    action: &'a str,
    package: &'a str,
    /// The version installed or removed (the new one for an upgrade).
    version: &'a str,
    old_version: &'a str,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let (kind, message) = match self.action {
            "installed" => ("package_installed", format!("installed {} {}", self.package, self.version)),
            "deinstalled" => ("package_removed", format!("removed {} {}", self.package, self.version)),
            "upgraded" => {
                ("package_upgraded", format!("upgraded {} {} -> {}", self.package, self.old_version, self.version))
            }
            _ => ("package_changed", format!("{} {} {}", self.action, self.package, self.version)),
        };
        self.time.map(|ts| Event::new(ts, kind, message)).into_iter()
    }
}

/// `name-version installed`, `name-version upgraded: 1.0 -> 1.1`.
fn classify(message: &str) -> Option<(&str, &str, &str, &str)> {
    let (full, rest) = message.split_once(' ')?;
    let (action, tail) = match rest.split_once(": ") {
        Some((action, tail)) => (action, tail),
        None => (rest, ""),
    };
    if !matches!(action, "installed" | "deinstalled" | "reinstalled" | "upgraded" | "downgraded") {
        return None;
    }
    let (package, version) = split_name_version(full);
    if package.is_empty() || version.is_empty() {
        return None;
    }
    // `upgraded: 1.0 -> 1.1` names both versions; `full` then holds the old one.
    match tail.split_once(" -> ") {
        Some((old, new)) => Some((action, package, new.trim(), old.trim())),
        None => Some((action, package, version, "")),
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_header(input, |offset, h| {
        if h.program != "pkg" {
            return Ok(());
        }
        let Some((action, package, version, old_version)) = classify(&h.message) else { return Ok(()) };
        sink.emit(
            Loc::Offset(offset),
            &Entry { time: h.time, time_basis: h.time.map(|t| t.basis), action, package, version, old_version },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn pkg_lines_in_a_real_messages_file() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/messages", &fixture("pkg-log/messages"), 1_794_600_000));
    }

    #[test]
    fn actions_and_versions() {
        let log = "Nov 13 01:08:26 h pkg[9]: gettext-runtime-1.0_1 installed\n\
                   Nov 13 01:08:27 h pkg[9]: zip-3.0_6 deinstalled\n\
                   Nov 13 01:08:28 h pkg[9]: sudo-1.9.17p2_2 reinstalled\n\
                   Nov 13 01:08:29 h pkg[9]: tree-2.3.1 upgraded: 2.3.1 -> 2.3.2\n\
                   Nov 13 01:08:30 h pkg[9]: nonsense\n\
                   Nov 13 01:08:31 h kernel: pkg-looking-1.0 installed\n";
        let out = run(&ARTIFACT, "var/log/messages", log.as_bytes(), 1_794_600_000);
        assert_eq!(out.lines().take_while(|l| l.starts_with('{')).count(), 4, "{out}");
        assert!(
            out.contains(
                "\"action\":\"upgraded\",\"package\":\"tree\",\"version\":\"2.3.2\",\"old_version\":\"2.3.1\""
            ),
            "{out}"
        );
        assert!(out.contains("package_removed") && out.contains("package_installed"));
    }
}
