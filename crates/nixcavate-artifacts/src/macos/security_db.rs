//! Two SQLite stores that record security decisions: the authorization database (`auth.db`) and
//! Gatekeeper's `ExecPolicy`.
//!
//! `auth.db`: table `rules` (`name`, `type` 1 right or 2 rule, `class` 1 user, 2 rule,
//! 3 evaluate-mechanisms, 4 allow, 5 deny, `group`, `created` and `modified` as Mac absolute
//! time, `identifier`, `comment`), `delegates_map` (rule to delegate rules) and `mechanisms_map`
//! / `mechanisms` (plugin and parameter). Class values and layout follow Apple's open-source
//! Security framework (`authorization.plist` and `authdb.c`, read for the class numbering).
//!
//! `ExecPolicy`: Gatekeeper's record of the executables it assessed: `policy_scan_cache` and
//! `executable_measurements_v2` (bundle id, signing id, team id, cdhash, flags, times), as
//! described in public write-ups of the database. Strong evidence that a binary was assessed
//! (so was run or opened) on this system.
//!
//! Synthetic only: no real `auth.db` or `ExecPolicy` was read. Doubts: the time columns of
//! `ExecPolicy` are taken as Unix seconds and dropped (with a warning) when not plausible as
//! such; column names of `ExecPolicy` vary between releases, so only the columns that exist
//! are read.

use super::plist_util::{mac_time, or_warn};
use super::tcc::select_columns;
use super::util::{clip, table_names};
use crate::sqlite::{int_at, open, open_with_tables, real_at, sql_error, text_at};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use rusqlite::types::ValueRef;
use serde::Serialize;
use std::collections::HashMap;

pub const AUTH_DB: Artifact = Artifact::new(
    "auth-db",
    "Authorization database: rights, rules and their mechanisms",
    Category::Security,
    MACOS,
    &["private/var/db/auth.db", "var/db/auth.db"],
    parse_auth,
)
.companions(&["private/var/db/auth.db-wal", "var/db/auth.db-wal"]);

pub const EXEC_POLICY: Artifact = Artifact::new(
    "exec-policy",
    "Gatekeeper ExecPolicy: executables assessed (bundle, signer, hash)",
    Category::Execution,
    MACOS,
    &["private/var/db/SystemPolicyConfiguration/ExecPolicy", "var/db/SystemPolicyConfiguration/ExecPolicy"],
    parse_exec_policy,
)
.companions(&[
    "private/var/db/SystemPolicyConfiguration/ExecPolicy-wal",
    "var/db/SystemPolicyConfiguration/ExecPolicy-wal",
]);

/// A rule changed this long after it was created is reported on the timeline: rules are
/// created and last modified together when the system is installed.
const CHANGED_AFTER_SECS: i64 = 86_400;
const MAX_LIST: usize = 64;

#[derive(Serialize)]
struct Rule {
    name: String,
    /// `right` or `rule`.
    rule_type: String,
    class: String,
    group: Option<String>,
    created: Option<Timestamp>,
    modified: Option<Timestamp>,
    delegates: Vec<String>,
    /// `plugin:parameter` of each mechanism, in order.
    mechanisms: Vec<String>,
    comment: Option<String>,
}

impl Record for Rule {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let changed = match (self.created, self.modified) {
            (Some(c), Some(m)) => m.utc.saturating_sub(c.utc) > CHANGED_AFTER_SECS * 1_000_000_000,
            _ => false,
        };
        let message = format!("authorization rule {} ({}) changed after creation", self.name, self.class);
        self.modified.filter(|_| changed).map(|ts| Event::new(ts, "authdb_rule_changed", message)).into_iter()
    }
}

fn class_name(class: Option<i64>) -> String {
    match class {
        Some(1) => "user".into(),
        Some(2) => "rule".into(),
        Some(3) => "mechanisms".into(),
        Some(4) => "allow".into(),
        Some(5) => "deny".into(),
        Some(n) => n.to_string(),
        None => String::new(),
    }
}

/// `rule id -> text` for a query returning `(id, text)` rows in the order wanted; a missing
/// table or a failing query gives an empty map.
fn lists(db: &crate::sqlite::Database, sql: &str, sink: &mut Sink) -> HashMap<i64, Vec<String>> {
    let mut map: HashMap<i64, Vec<String>> = HashMap::new();
    let mut stmt = match db.conn.prepare(sql) {
        Ok(stmt) => stmt,
        Err(e) => {
            sink.warn(format!("rule delegates or mechanisms not read: {e}"));
            return map;
        }
    };
    let Ok(mut rows) = stmt.query([]) else { return map };
    while let Ok(Some(row)) = rows.next() {
        if let (Some(id), Some(text)) = (int_at(row, 0), text_at(row, 1)) {
            let list = map.entry(id).or_default();
            if list.len() < MAX_LIST {
                list.push(clip(&text, 256));
            }
        }
    }
    map
}

fn parse_auth(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["rules"])?;
    let cols =
        select_columns(&db, "rules", &["id", "name", "type", "class", "group", "created", "modified", "comment"])?;
    let (delegates, mechanisms) = if db.has_table("delegates_map")
        && db.has_table("mechanisms_map")
        && db.has_table("mechanisms")
    {
        db.refuse_generated_columns(&["delegates_map", "mechanisms_map", "mechanisms"])?;
        (
            lists(&db, "SELECT m.r_id, d.name FROM delegates_map m JOIN rules d ON d.id = m.d_id ORDER BY m.r_id, m.ord", sink),
            lists(
                &db,
                "SELECT mm.r_id, s.plugin || ':' || s.param FROM mechanisms_map mm JOIN mechanisms s ON s.id = mm.m_id \
                 ORDER BY mm.r_id, mm.ord",
                sink,
            ),
        )
    } else {
        (HashMap::new(), HashMap::new())
    };
    let sql = format!("SELECT {} FROM rules ORDER BY name, rowid", cols.join(", "));
    let mut stmt = db.conn.prepare(&sql).map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let id = int_at(row, 0);
        // Zero is the column default, "never set".
        let created = or_warn(sink, "created", real_at(row, 5).filter(|&t| t != 0.0), mac_time);
        let modified = or_warn(sink, "modified", real_at(row, 6).filter(|&t| t != 0.0), mac_time);
        sink.emit(
            Loc::None,
            &Rule {
                name: text_at(row, 1).unwrap_or_default(),
                rule_type: match int_at(row, 2) {
                    Some(1) => "right".into(),
                    Some(2) => "rule".into(),
                    other => other.map(|n| n.to_string()).unwrap_or_default(),
                },
                class: class_name(int_at(row, 3)),
                group: text_at(row, 4),
                created,
                modified,
                delegates: id.and_then(|i| delegates.get(&i)).cloned().unwrap_or_default(),
                mechanisms: id.and_then(|i| mechanisms.get(&i)).cloned().unwrap_or_default(),
                comment: text_at(row, 7).map(|c| clip(&c, 256)),
            },
        )?;
    }
    Ok(())
}

#[derive(Serialize)]
struct Executable {
    /// The table the row came from.
    table: String,
    bundle_id: Option<String>,
    signing_id: Option<String>,
    team_id: Option<String>,
    cdhash: Option<String>,
    volume_uuid: Option<String>,
    object_id: Option<i64>,
    policy_match: Option<i64>,
    flags: Option<i64>,
    /// The executable's modification time as Gatekeeper recorded it.
    mod_time: Option<Timestamp>,
    /// When Gatekeeper recorded the measurement.
    time: Option<Timestamp>,
}

impl Record for Executable {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let what = self.signing_id.as_deref().or(self.bundle_id.as_deref()).unwrap_or("an executable");
        let message = format!("Gatekeeper assessed {what}");
        self.time.map(|ts| Event::new(ts, "executed", message)).into_iter()
    }
}

/// Unix seconds between 2000 and 2100: the only values taken as a time.
fn unix_time(secs: i64) -> Option<Timestamp> {
    (946_684_800..4_102_444_800)
        .contains(&secs)
        .then(|| Timestamp::from_secs_nanos(secs, 0, Precision::Seconds, Basis::Recorded))
}

fn hex(row: &rusqlite::Row, i: usize) -> Option<String> {
    match row.get_ref(i).ok()? {
        ValueRef::Blob(b) => Some(b.iter().map(|x| format!("{x:02x}")).collect()),
        ValueRef::Null => None,
        _ => text_at(row, i),
    }
}

fn parse_exec_policy(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open(input)?;
    let names = table_names(&db)?;
    let mut any = false;
    for table in ["policy_scan_cache", "executable_measurements_v2", "executable_measurements"] {
        if !names.iter().any(|n| n == table) {
            continue;
        }
        any = true;
        db.refuse_generated_columns(&[table])?;
        let cols = select_columns(
            &db,
            table,
            &[
                "bundle_id",
                "signing_identifier",
                "team_identifier",
                "cdhash",
                "volume_uuid",
                "object_id",
                "policy_match",
                "flags",
                "mod_time",
                "timestamp",
            ],
        )?;
        let sql = format!("SELECT {} FROM {table} ORDER BY rowid", cols.join(", "));
        let mut stmt = db.conn.prepare(&sql).map_err(sql_error)?;
        let mut rows = stmt.query([]).map_err(sql_error)?;
        let mut implausible = 0u32;
        while let Some(row) = rows.next().map_err(sql_error)? {
            let mut convert = |i: usize| {
                let raw = int_at(row, i);
                let t = raw.and_then(unix_time);
                if raw.is_some() && t.is_none() {
                    implausible += 1;
                }
                t
            };
            let (mod_time, time) = (convert(8), convert(9));
            sink.emit(
                Loc::None,
                &Executable {
                    table: table.to_string(),
                    bundle_id: text_at(row, 0),
                    signing_id: text_at(row, 1),
                    team_id: text_at(row, 2),
                    cdhash: hex(row, 3),
                    volume_uuid: text_at(row, 4),
                    object_id: int_at(row, 5),
                    policy_match: int_at(row, 6),
                    flags: int_at(row, 7),
                    mod_time,
                    time,
                },
            )?;
        }
        if implausible > 0 {
            sink.warn(format!("{table}: {implausible} time values are not plausible Unix seconds; left empty"));
        }
    }
    if !any {
        return Err(Error::skipped("no ExecPolicy tables"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::database_bytes;
    use crate::testing::{fixture, run};

    const AUTH: &str = "private/var/db/auth.db";
    const EXEC: &str = "private/var/db/SystemPolicyConfiguration/ExecPolicy";

    #[test]
    fn auth_rules_with_delegates_and_mechanisms() {
        insta::assert_snapshot!(run(&AUTH_DB, AUTH, &fixture("security-db/auth.db"), 0));
    }

    #[test]
    fn exec_policy_rows_and_implausible_times() {
        insta::assert_snapshot!(run(&EXEC_POLICY, EXEC, &fixture("security-db/ExecPolicy"), 0));
    }

    #[test]
    fn other_databases_are_skipped() {
        let db = database_bytes("CREATE TABLE t (a);");
        assert!(run(&AUTH_DB, AUTH, &db, 0).contains("skipped: no rules table"));
        assert!(run(&EXEC_POLICY, EXEC, &db, 0).contains("skipped: no ExecPolicy tables"));
    }

    #[test]
    fn damaged_databases_do_not_panic() {
        crate::macos::util::survives_sparse(&AUTH_DB, AUTH, &fixture("security-db/auth.db"), 701, 30);
        crate::macos::util::survives_sparse(&EXEC_POLICY, EXEC, &fixture("security-db/ExecPolicy"), 701, 30);
    }
}
