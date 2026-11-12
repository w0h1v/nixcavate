//! Local accounts from the Directory Services store: one plist per user under
//! `/var/db/dslocal/nodes/Default/users/`. Each plist maps an attribute name to an array of
//! values. `accountPolicyData` and `ShadowHashData` hold nested plists as data.
//! Format: Apple's property list format (`plist(5)`); attribute names as used by
//! `dscl . -read /Users/<name>`.
//!
//! Privacy: only the top-level key NAMES of the nested `ShadowHashData` plist are reported
//! (the hash types), and only names that are at most 64 characters of `[A-Za-z0-9._-]`. The
//! hash, salt and verifier bytes are never read into a record, whatever shape the plist has.

use super::plist_util::{date, integer, or_warn, parse, strings};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use plist::{Dictionary, Value};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "dslocal-users",
    "Local user accounts (Directory Services)",
    Category::Accounts,
    MACOS,
    &["private/var/db/dslocal/nodes/Default/users/*.plist"],
    parse_account,
);

#[derive(Serialize)]
struct Account {
    user: Option<String>,
    uid: Option<i64>,
    gid: Option<i64>,
    real_name: Option<String>,
    home: Option<String>,
    shell: Option<String>,
    generated_uid: Option<String>,
    hidden: bool,
    hash_types: Vec<String>,
    secure_token: bool,
    /// Account creation (`creationTime` of the account policy).
    time: Option<Timestamp>,
    password_last_set_time: Option<Timestamp>,
    failed_login_count: Option<i64>,
    failed_login_time: Option<Timestamp>,
}

impl Record for Account {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let name = self.user.as_deref().unwrap_or("unknown");
        let created = self.time.map(|ts| Event::new(ts, "account_created", format!("account {name} created")));
        let changed = self
            .password_last_set_time
            .map(|ts| Event::new(ts, "password_changed", format!("password of {name} changed")));
        created.into_iter().chain(changed)
    }
}

/// The first value of an attribute; a bare value (not wrapped in an array) is accepted too.
fn first<'a>(root: &'a Dictionary, key: &str) -> Option<&'a Value> {
    match root.get(key)? {
        Value::Array(items) => items.first(),
        other => Some(other),
    }
}

/// A nested plist stored as data; unreadable or wrong-typed content gives `None`.
fn nested(root: &Dictionary, key: &str) -> Option<Dictionary> {
    let Value::Data(bytes) = first(root, key)? else { return None };
    parse(bytes).ok()?.into_dictionary()
}

/// An attribute number. Directory Services stores them as strings (`"501"`), so text is parsed.
fn number(root: &Dictionary, key: &str) -> Option<i64> {
    match first(root, key)? {
        Value::Integer(i) => i.as_signed(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// An attribute flag: a boolean, or the text `1`/`true`/`yes` and `0`/`false`/`no`.
fn flag(root: &Dictionary, key: &str) -> Option<bool> {
    match first(root, key)? {
        Value::Boolean(b) => Some(*b),
        Value::Integer(i) => i.as_signed().map(|n| n != 0),
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" => Some(true),
            "0" | "false" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

const MAX_HASH_NAME: usize = 64;

/// A top-level key name of `ShadowHashData` that is safe to report. The name is attacker
/// controlled, so anything that is not a short plain identifier is dropped.
fn hash_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HASH_NAME
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// An account-policy time: Unix epoch seconds as a real or integer (a plist date is accepted
/// too). `None` with a warning when present but not a usable time.
fn policy_time(sink: &mut Sink, key: &str, value: Option<&Value>) -> Option<Timestamp> {
    let precision = |secs: f64| if secs.fract() == 0.0 { Precision::Seconds } else { Precision::Micros };
    match value? {
        Value::Real(r) => or_warn(sink, key, Some(*r), |s| Timestamp::from_secs_f64(s, precision(s), Basis::Recorded)),
        Value::Integer(i) => {
            or_warn(sink, key, i.as_signed(), |s| Timestamp::checked(s, 0, Precision::Seconds, Basis::Recorded))
        }
        other @ Value::Date(_) => {
            let time = date(other);
            if time.is_none() {
                sink.warn(format!("{key} is not a valid time; left empty"));
            }
            time
        }
        _ => None,
    }
}

fn parse_account(input: &Input, sink: &mut Sink) -> Result<()> {
    let root = parse(input.data)?;
    let Some(root) = root.as_dictionary() else {
        return Err(Error::skipped("not a dictionary"));
    };
    if !root.contains_key("name") {
        return Err(Error::skipped("no name attribute"));
    }
    let policy = nested(root, "accountPolicyData");
    let policy_value = |key: &str| policy.as_ref().and_then(|p| p.get(key));
    let mut hash_types = Vec::new();
    for name in nested(root, "ShadowHashData").iter().flat_map(|d| d.keys()) {
        if hash_name(name) {
            hash_types.push(name.clone());
        } else {
            sink.warn("ShadowHashData has a key name that is not a plain identifier; not reported");
        }
    }
    let secure_token = match root.get("authentication_authority") {
        Some(value) => strings(value).iter().any(|a| a.contains(";SecureToken;")),
        None => false,
    };
    let time = policy_time(sink, "creationTime", policy_value("creationTime"));
    let password_last_set_time = policy_time(sink, "passwordLastSetTime", policy_value("passwordLastSetTime"));
    let failed_login_time = policy_time(sink, "failedLoginTimestamp", policy_value("failedLoginTimestamp"));
    let text = |key: &str| first(root, key).and_then(Value::as_string).map(str::to_owned);
    sink.emit(
        Loc::None,
        &Account {
            user: text("name"),
            uid: number(root, "uid"),
            gid: number(root, "gid"),
            real_name: text("realname"),
            home: text("home"),
            shell: text("shell"),
            generated_uid: text("generateduid"),
            hidden: flag(root, "IsHidden").unwrap_or(false),
            hash_types,
            secure_token,
            time,
            password_last_set_time,
            failed_login_count: policy.as_ref().and_then(|p| integer(p, "failedLoginCount")),
            failed_login_time,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const DIR: &str = "private/var/db/dslocal/nodes/Default/users";

    fn path(name: &str) -> String {
        format!("{DIR}/{name}")
    }

    #[test]
    fn parses_accounts() {
        let out: String = ["alice.plist", "_hidden.plist", "odd.plist"]
            .iter()
            .map(|name| run(&ARTIFACT, &path(name), &fixture(&format!("dslocal-users/{name}")), 0))
            .collect();
        insta::assert_snapshot!(out);
    }

    #[test]
    fn hash_material_is_never_output() {
        let data = fixture("dslocal-users/alice.plist");
        let marker = b"MARKER-SALT-0123456789ABCDEF";
        // The fixture really carries the marker, inside the nested ShadowHashData.
        let nested = {
            let root = parse(&data).unwrap();
            let Some(Value::Data(bytes)) = first(root.as_dictionary().unwrap(), "ShadowHashData").cloned() else {
                panic!("fixture has no ShadowHashData");
            };
            bytes
        };
        assert!(nested.windows(marker.len()).any(|w| w == marker));
        let out = run(&ARTIFACT, &path("alice.plist"), &data, 0);
        assert!(out.contains("SALTED-SHA512-PBKDF2"), "{out}");
        for needle in ["MARKER", "entropy", "verifier", "45000"] {
            assert!(!out.contains(needle), "{needle} leaked: {out}");
        }
        let hex: String = marker.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!out.to_lowercase().contains(&hex));
    }

    fn xml(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        value.to_writer_xml(&mut out).unwrap();
        out
    }

    fn dict(items: Vec<(&str, Value)>) -> Value {
        Value::Dictionary(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    fn account(extra: Vec<(&str, Value)>) -> Vec<u8> {
        let mut items = vec![("name", Value::Array(vec![Value::String("bob".into())]))];
        items.extend(extra);
        xml(&dict(items))
    }

    #[test]
    fn hash_material_is_never_output_whatever_the_shape() {
        let secret = || Value::Data(b"LEAK0123SECRETBYTES".to_vec());
        let shadow = |inner: Value| Value::Array(vec![Value::Data(xml(&inner))]);
        let long_name = "N".repeat(65);
        let cases: Vec<(&str, Value)> = vec![
            ("string", Value::String("LEAK0123SECRETBYTES".into())),
            ("bare data", Value::Data(xml(&dict(vec![("SALTED-SHA512-PBKDF2", dict(vec![("entropy", secret())]))])))),
            ("string array", Value::Array(vec![Value::String("LEAK0123SECRETBYTES".into())])),
            (
                "several blobs",
                Value::Array(vec![
                    Value::Data(xml(&dict(vec![("SALTED-SHA512-PBKDF2", dict(vec![("entropy", secret())]))]))),
                    Value::Data(xml(&dict(vec![("OTHER", secret())]))),
                    secret(),
                ]),
            ),
            (
                "deeper",
                shadow(dict(vec![("SALTED-SHA512-PBKDF2", Value::Data(xml(&dict(vec![("entropy", secret())]))))])),
            ),
            ("array root", shadow(Value::Array(vec![secret(), Value::String("LEAK0123".into())]))),
            ("unexpected key", shadow(dict(vec![("password", Value::String("LEAK0123SECRETBYTES".into()))]))),
            ("secret as bad key", shadow(dict(vec![("LEAK0123+/=SECRETBYTES", secret())]))),
            ("secret with newline", shadow(dict(vec![("LEAK0123\nSECRETBYTES", secret())]))),
            ("secret as long key", shadow(dict(vec![(long_name.as_str(), secret())]))),
            ("secret as non-ascii key", shadow(dict(vec![("LEAK0123\u{e9}", secret())]))),
        ];
        for (shape, value) in cases {
            let out = run(&ARTIFACT, &path("bob.plist"), &account(vec![("ShadowHashData", value)]), 0);
            for needle in ["LEAK", "SECRET", "entropy", "TEJBSzAxMjM", "NNNNNNNNNN"] {
                assert!(!out.contains(needle), "{shape}: {needle} leaked: {out}");
            }
            let hex: String = b"LEAK0123SECRETBYTES".iter().map(|b| format!("{b:02x}")).collect();
            assert!(!out.to_lowercase().contains(&hex), "{shape}: {out}");
            assert!(out.contains("\"user\":\"bob\""), "{shape}: {out}");
        }
        // A plain name is still reported, and the unexpected key's value is not.
        let value = shadow(dict(vec![("password", Value::String("LEAK0123".into()))]));
        let out = run(&ARTIFACT, &path("bob.plist"), &account(vec![("ShadowHashData", value)]), 0);
        assert!(out.contains("\"hash_types\":[\"password\"]"), "{out}");
    }

    #[test]
    fn absurd_policy_times_are_dropped_with_a_warning() {
        let policy = |value: Value| {
            let inner = dict(vec![
                ("creationTime", value),
                ("passwordLastSetTime", Value::Integer(i64::MAX.into())),
                ("failedLoginTimestamp", Value::Real(f64::NAN)),
            ]);
            account(vec![("accountPolicyData", Value::Array(vec![Value::Data(xml(&inner))]))])
        };
        let out = run(&ARTIFACT, &path("bob.plist"), &policy(Value::Real(1e300)), 0);
        assert!(out.contains("\"time\":null") && out.contains("\"password_last_set_time\":null"), "{out}");
        assert!(out.contains("\"failed_login_time\":null"), "{out}");
        assert_eq!(out.matches("is not a valid time").count(), 3, "{out}");
        assert!(!out.contains("2262"), "{out}");
    }

    #[test]
    fn other_inputs_are_not_parsed() {
        assert!(run(&ARTIFACT, &path("x.plist"), b"", 0).contains("skipped: empty file"));
        assert!(run(&ARTIFACT, &path("x.plist"), b"junk", 0).contains("failed: "));
        let unrelated = fixture("wifi-networks/unrelated.plist");
        assert!(run(&ARTIFACT, &path("x.plist"), &unrelated, 0).contains("skipped: no name attribute"));
    }

    #[test]
    fn damaged_files_do_not_panic() {
        let data = fixture("dslocal-users/alice.plist");
        for len in 0..data.len() {
            run(&ARTIFACT, &path("a.plist"), &data[..len], 0);
        }
        let mut seed = 13u32;
        for _ in 0..300 {
            let mut copy = data.clone();
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let at = (seed >> 8) as usize % copy.len();
            copy[at] ^= (seed & 0xff) as u8 | 1;
            run(&ARTIFACT, &path("a.plist"), &copy, 0);
        }
    }
}
