//! Gatekeeper and XProtect state.
//!
//! `gatekeeper-policy`: the `authority` table of the `SystemPolicy` SQLite database (rules
//! `spctl` evaluates; layout as printed by `spctl --list` documentation and public Gatekeeper
//! research). `ctime`/`mtime` are Julian day numbers.
//!
//! `xprotect-meta`: version information of the XProtect bundle (`Info.plist`) and its
//! `XProtect.meta.plist` (`Version`, `PluginBlacklist`, `ExtensionBlacklist`).

use super::plist_util::{or_warn, parse};
use super::tcc::select_columns;
use crate::sqlite::{int_at, open_with_tables, real_at, sql_error, text_at};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use plist::Value;
use serde::Serialize;

pub const POLICY: Artifact = Artifact::new(
    "gatekeeper-policy",
    "Gatekeeper assessment rules (SystemPolicy)",
    Category::Security,
    MACOS,
    &["private/var/db/SystemPolicy", "private/var/db/SystemPolicyConfiguration/SystemPolicy"],
    parse_policy,
)
.companions(&["private/var/db/SystemPolicy-wal", "private/var/db/SystemPolicyConfiguration/SystemPolicy-wal"]);

pub const XPROTECT: Artifact = Artifact::new(
    "xprotect-meta",
    "XProtect bundle and malware-definition versions",
    Category::Security,
    MACOS,
    &[
        "Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
        "Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist",
        "System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
    ],
    parse_xprotect,
);

#[derive(Serialize)]
struct Rule {
    rule_id: Option<i64>,
    rule_type: String,
    label: Option<String>,
    requirement: Option<String>,
    allow: Option<bool>,
    disabled: Option<bool>,
    priority: Option<f64>,
    time: Option<Timestamp>,
    created_time: Option<Timestamp>,
    remarks: Option<String>,
}

impl Record for Rule {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "{} rule {} ({}): {}",
            self.rule_type,
            self.rule_id.map(|i| i.to_string()).unwrap_or_default(),
            self.label.as_deref().unwrap_or("no label"),
            if self.allow == Some(true) { "allow" } else { "deny" }
        );
        self.time.map(|ts| Event::new(ts, "gatekeeper_rule", message)).into_iter()
    }
}

fn rule_type(value: Option<i64>) -> String {
    match value {
        Some(1) => "execute".into(),
        Some(2) => "install".into(),
        Some(3) => "open".into(),
        Some(n) => n.to_string(),
        None => String::new(),
    }
}

fn julian_day(day: f64) -> Option<Timestamp> {
    let secs = (day - 2_440_587.5) * 86_400.0;
    let precision = if secs.fract() == 0.0 { Precision::Seconds } else { Precision::Micros };
    Timestamp::from_secs_f64(secs, precision, Basis::Recorded)
}

fn parse_policy(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["authority"])?;
    let names = ["id", "type", "label", "requirement", "allow", "disabled", "priority", "mtime", "ctime", "remarks"];
    let list = select_columns(&db, "authority", &names)?;
    let sql = format!("SELECT {} FROM authority ORDER BY rowid", list.join(", "));
    let mut statement = db.conn.prepare(&sql).map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let time = or_warn(sink, "mtime", real_at(row, 7).filter(|&d| d != 0.0), julian_day);
        let created_time = or_warn(sink, "ctime", real_at(row, 8).filter(|&d| d != 0.0), julian_day);
        sink.emit(
            Loc::None,
            &Rule {
                rule_id: int_at(row, 0),
                rule_type: rule_type(int_at(row, 1)),
                label: text_at(row, 2),
                requirement: text_at(row, 3),
                allow: int_at(row, 4).map(|v| v != 0),
                disabled: int_at(row, 5).map(|v| v != 0),
                priority: real_at(row, 6),
                time,
                created_time,
                remarks: text_at(row, 9),
            },
        )?;
    }
    Ok(())
}

#[derive(Serialize)]
struct Meta {
    bundle_version: Option<String>,
    build_version: Option<String>,
    meta_version: Option<String>,
    plugin_blacklist_count: Option<u64>,
    extension_blacklist_count: Option<u64>,
    /// The file's own modification time as collected, not a recorded event.
    modified: Option<Timestamp>,
}

impl Record for Meta {}

fn count(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Array(items) => Some(items.len() as u64),
        Value::Dictionary(items) => Some(items.len() as u64),
        _ => None,
    }
}

/// A version: XProtect writes `Version` as an integer and the bundle keys as strings.
fn version(root: &plist::Dictionary, key: &str) -> Option<String> {
    match root.get(key)? {
        Value::String(s) => Some(s.clone()),
        Value::Integer(i) => Some(i.to_string()),
        _ => None,
    }
}

fn parse_xprotect(input: &Input, sink: &mut Sink) -> Result<()> {
    let root = parse(input.data)?;
    let Some(root) = root.as_dictionary() else {
        return Err(Error::skipped("not a dictionary"));
    };
    let modified = or_warn(sink, "file modification time", Some(input.mtime).filter(|&m| m != 0), |m| {
        Timestamp::checked(m, 0, Precision::Seconds, Basis::Recorded)
    });
    sink.emit(
        Loc::None,
        &Meta {
            bundle_version: version(root, "CFBundleShortVersionString"),
            build_version: version(root, "CFBundleVersion"),
            meta_version: version(root, "Version"),
            plugin_blacklist_count: count(root.get("PluginBlacklist")),
            extension_blacklist_count: count(root.get("ExtensionBlacklist")),
            modified,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const POLICY_PATH: &str = "private/var/db/SystemPolicy";
    const META: &str =
        "Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist";
    const INFO: &str = "System/Library/CoreServices/XProtect.bundle/Contents/Info.plist";

    #[test]
    fn parses_policy_rules() {
        insta::assert_snapshot!(run(&POLICY, POLICY_PATH, &fixture("gatekeeper-policy/SystemPolicy"), 0));
    }

    #[test]
    fn policy_inputs_that_are_not_policies_are_skipped() {
        assert!(run(&POLICY, POLICY_PATH, b"", 0).contains("skipped: not an SQLite database"));
        let other = fixture("tcc/not-tcc.db");
        assert!(run(&POLICY, POLICY_PATH, &other, 0).contains("skipped: no authority table"));
    }

    #[test]
    fn parses_xprotect_files() {
        let out = [
            run(&XPROTECT, INFO, &fixture("xprotect-meta/Info.plist"), 1_700_000_000),
            run(&XPROTECT, META, &fixture("xprotect-meta/XProtect.meta.plist"), 0),
            run(&XPROTECT, INFO, &fixture("xprotect-meta/Info-wrong-types.plist"), 0),
        ];
        insta::assert_snapshot!(out.join(""));
    }

    #[test]
    fn xprotect_empty_and_damaged_files() {
        assert!(run(&XPROTECT, INFO, b"", 0).contains("skipped: empty file"));
        let data = fixture("xprotect-meta/XProtect.meta.plist");
        for len in 0..data.len() {
            run(&XPROTECT, META, &data[..len], 0);
        }
        let mut seed = 5u32;
        for _ in 0..200 {
            let mut copy = data.clone();
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let at = (seed >> 8) as usize % copy.len();
            copy[at] ^= (seed & 0xff) as u8 | 1;
            run(&XPROTECT, META, &copy, 0);
        }
    }

    #[test]
    fn absurd_times_are_dropped_with_a_warning() {
        let db = crate::sqlite::database_bytes(
            "CREATE TABLE authority (id INTEGER PRIMARY KEY, type INTEGER, mtime REAL, ctime);
             INSERT INTO authority VALUES (1, 1, 1e300, 9223372036854775807);",
        );
        let out = run(&POLICY, POLICY_PATH, &db, 0);
        assert!(out.contains("\"time\":null") && out.contains("\"created_time\":null"), "{out}");
        assert_eq!(out.matches("is not a valid time").count(), 2, "{out}");
        assert!(!out.contains("2262"), "{out}");
        let out = run(&XPROTECT, INFO, &fixture("xprotect-meta/Info.plist"), i64::MAX);
        assert!(out.contains("\"modified\":null") && out.contains("is not a valid time"), "{out}");
    }

    #[test]
    fn damaged_policy_databases_do_not_panic() {
        let data = fixture("gatekeeper-policy/SystemPolicy");
        for len in (0..data.len()).step_by(997) {
            run(&POLICY, POLICY_PATH, &data[..len], 0);
        }
        let mut seed = 9u32;
        for _ in 0..20 {
            let mut copy = data.clone();
            for _ in 0..8 {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let at = (seed >> 8) as usize % copy.len();
                copy[at] ^= (seed & 0xff) as u8 | 1;
            }
            run(&POLICY, POLICY_PATH, &copy, 0);
        }
    }
}
