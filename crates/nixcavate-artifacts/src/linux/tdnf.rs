//! Photon OS package history: tdnf's `history.db` (SQLite; `/usr/lib/sysimage/tdnf/history.db`
//! on Photon 5, `/var/lib/tdnf/history.db` before). Schema from tdnf's `history` module,
//! checked against a database written by tdnf 3.5 on Photon 5:
//! `transactions(Id, cookie, cmdline, timestamp, type)`, `trans_items(Id, trans_id, type,
//! rpm_id)` and `rpms(Id, nevra)`. A transaction's items are the packages it added (type 1)
//! or removed (type 2); the first transaction is a baseline snapshot of what was installed
//! when history began.

use crate::sqlite::{int_at, open_with_tables, sql_error, text_at};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const HISTORY: Artifact = Artifact::new(
    "tdnf-history",
    "Photon tdnf transaction history",
    Category::Software,
    LINUX,
    &["usr/lib/sysimage/tdnf/history.db", "var/lib/tdnf/history.db"],
    parse,
)
.companions(&["usr/lib/sysimage/tdnf/history.db-wal", "var/lib/tdnf/history.db-wal"]);

#[derive(Serialize)]
struct Item {
    time: Option<Timestamp>,
    transaction_id: i64,
    /// `baseline` for the snapshot that starts the history, `transaction` for the rest.
    kind: &'static str,
    command: String,
    /// `added` or `removed`; empty for a transaction that changed nothing.
    action: &'static str,
    /// The package as tdnf stores it: `name-version-release.arch`.
    package: String,
    name: String,
    version: String,
    release: String,
    architecture: String,
}

impl Record for Item {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let (kind, message) = match (self.action, self.kind) {
            ("added", _) => ("package_installed", format!("added {} ({})", self.package, self.command)),
            ("removed", _) => ("package_removed", format!("removed {} ({})", self.package, self.command)),
            (_, "transaction") => ("package_command", format!("tdnf {}", self.command)),
            _ => return None.into_iter(),
        };
        self.time.map(|time| Event::new(time, kind, message)).into_iter()
    }
}

/// Splits `name-version-release.arch`; a name that does not fit (`gpg-pubkey-<id>-<id>` has no
/// architecture) is split as far as it goes.
fn split_nevra(nevra: &str) -> (&str, &str, &str, &str) {
    let (rest, arch) = match nevra.rsplit_once('.') {
        Some((rest, arch)) if !arch.contains('-') => (rest, arch),
        _ => (nevra, ""),
    };
    let Some((rest, release)) = rest.rsplit_once('-') else { return (rest, "", "", arch) };
    let Some((name, version)) = rest.rsplit_once('-') else { return (rest, "", release, arch) };
    (name, version, release, arch)
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["transactions", "trans_items", "rpms"])?;
    // Left joins: a transaction with no items (an aborted run, the baseline) still shows.
    let mut statement = db
        .conn
        .prepare(
            "SELECT t.Id, t.timestamp, t.cmdline, t.type, i.type, r.nevra \
             FROM transactions t LEFT JOIN trans_items i ON i.trans_id = t.Id \
             LEFT JOIN rpms r ON r.Id = i.rpm_id ORDER BY t.Id, i.Id",
        )
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let package = text_at(row, 5).unwrap_or_default();
        let (name, version, release, architecture) = split_nevra(&package);
        let item = Item {
            time: int_at(row, 1)
                .and_then(|secs| Timestamp::checked(secs, 0, nixcavate_core::Precision::Seconds, Basis::Recorded)),
            transaction_id: int_at(row, 0).unwrap_or(0),
            kind: if int_at(row, 3) == Some(0) { "baseline" } else { "transaction" },
            command: text_at(row, 2).unwrap_or_default(),
            action: match (int_at(row, 4), package.is_empty()) {
                (Some(1), false) => "added",
                (Some(2), false) => "removed",
                _ => "",
            },
            name: name.to_string(),
            version: version.to_string(),
            release: release.to_string(),
            architecture: architecture.to_string(),
            package,
        };
        sink.emit(Loc::None, &item)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn parses_a_real_history() {
        insta::assert_snapshot!(run(
            &HISTORY,
            "usr/lib/sysimage/tdnf/history.db",
            &fixture("tdnf-history/history.db"),
            0
        ));
    }

    #[test]
    fn splits_nevra() {
        assert_eq!(split_nevra("tree-2.0.4-2.ph5.aarch64"), ("tree", "2.0.4", "2.ph5", "aarch64"));
        assert_eq!(split_nevra("gpg-pubkey-36e4-4803fe57"), ("gpg-pubkey", "36e4", "4803fe57", ""));
        assert_eq!(split_nevra("bare"), ("bare", "", "", ""));
        assert_eq!(split_nevra(""), ("", "", "", ""));
    }

    #[test]
    fn rejects_other_files() {
        let path = "usr/lib/sysimage/tdnf/history.db";
        assert!(run(&HISTORY, path, b"text", 0).contains("skipped: not an SQLite database"));
        let rpmdb = fixture("rpm-db/rpmdb.sqlite");
        assert!(run(&HISTORY, path, &rpmdb, 0).contains("skipped: no transactions table"));
    }

    #[test]
    fn mutated_databases_never_panic() {
        let db = fixture("tdnf-history/history.db");
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..150 {
            let mut copy = db.clone();
            for _ in 0..1 + next() % 6 {
                let at = (next() as usize) % copy.len();
                copy[at] = next() as u8;
            }
            let _ = run(&HISTORY, "usr/lib/sysimage/tdnf/history.db", &copy, 0);
        }
        for len in (0..db.len()).step_by(4096) {
            let _ = run(&HISTORY, "usr/lib/sysimage/tdnf/history.db", &db[..len], 0);
        }
    }
}
