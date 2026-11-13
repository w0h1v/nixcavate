//! Role-based access control. `etc/user_attr` says which profiles, authorizations and roles an
//! account has; `etc/security/prof_attr`, `exec_attr` and `auth_attr` define them (and the
//! `*.d/` fragments that packages install and the system merges into them). Format:
//! user_attr(5), prof_attr(5), exec_attr(5), auth_attr(5): colon-separated fields, `\:` for a
//! colon inside a field, and `key=value;key=value` attribute lists.
//!
//! Verified on illumos (OmniOS): every account of `etc/user_attr` and the profiles each user
//! holds equal `profiles` and `roles` output; the harness's added profile and `exec_attr`
//! entry that runs a program as uid 0 are read as such. The Solaris Trusted Extensions label
//! attributes (`min_label`, `clearance`) are kept as text and not interpreted.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const USER_ATTR: Artifact = Artifact::new(
    "user-attr",
    "RBAC: roles, profiles and authorizations of each account (user_attr)",
    Category::Accounts,
    SOLARIS,
    &["etc/user_attr", "etc/user_attr.d/*"],
    parse_user_attr,
);

pub const RBAC: Artifact = Artifact::new(
    "rbac-profiles",
    "RBAC: execution profiles and the commands they run (prof_attr, exec_attr, auth_attr)",
    Category::Accounts,
    SOLARIS,
    &[
        "etc/security/prof_attr",
        "etc/security/exec_attr",
        "etc/security/auth_attr",
        "etc/security/prof_attr.d/*",
        "etc/security/exec_attr.d/*",
        "etc/security/auth_attr.d/*",
    ],
    parse_profiles,
);

/// Splits on `:` that is not escaped as `\:`; the escape is removed from the pieces only when
/// the caller asks (attribute text keeps it for `split_attrs`).
fn split_fields(line: &str) -> Vec<&str> {
    let (mut out, mut start, mut escaped) = (Vec::new(), 0, false);
    for (i, c) in line.char_indices() {
        match c {
            '\\' => escaped = !escaped,
            ':' if !escaped => {
                out.push(&line[start..i]);
                start = i + 1;
            }
            _ => escaped = false,
        }
    }
    out.push(&line[start..]);
    out
}

fn push_attr<'a>(out: &mut Vec<(&'a str, String)>, piece: &'a str) {
    if let Some((key, value)) = piece.split_once('=') {
        out.push((key.trim(), value.replace("\\:", ":").replace("\\;", ";")));
    }
}

/// `key=value;key=value` with `\;` and `\:` unescaped in the values.
fn attrs(text: &str) -> Vec<(&str, String)> {
    let (mut out, mut start, mut escaped) = (Vec::new(), 0, false);
    for (i, c) in text.char_indices() {
        match c {
            '\\' => escaped = !escaped,
            ';' if !escaped => {
                push_attr(&mut out, &text[start..i]);
                start = i + 1;
            }
            _ => escaped = false,
        }
    }
    push_attr(&mut out, &text[start..]);
    out
}

fn list(attrs: &[(&str, String)], key: &str) -> Vec<String> {
    attrs
        .iter()
        .filter(|(k, _)| *k == key)
        .flat_map(|(_, v)| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
        .collect()
}

fn value(attrs: &[(&str, String)], key: &str) -> String {
    attrs.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone()).unwrap_or_default()
}

#[derive(Serialize)]
struct UserAttr<'a> {
    user: &'a str,
    qualifier: &'a str,
    /// `normal` or `role` (the `type` attribute; empty when absent).
    account_type: String,
    profiles: Vec<String>,
    authorizations: Vec<String>,
    roles: Vec<String>,
    default_privileges: String,
    limit_privileges: String,
    project: String,
    /// Every attribute as written, for the ones above and for the rest (`lock_after_retries`, `audit_flags`, `min_label`...).
    attributes: String,
}

impl Record for UserAttr<'_> {}

fn parse_user_attr(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            return Ok(());
        }
        let fields = split_fields(text);
        let &[user, qualifier, _, _, attr] = &fields[..] else {
            sink.warn(format!("line {}: expected 5 fields, found {}", line.number, fields.len()));
            return Ok(());
        };
        let parsed = attrs(attr);
        sink.emit(
            Loc::Line(line.number),
            &UserAttr {
                user,
                qualifier,
                account_type: value(&parsed, "type"),
                profiles: list(&parsed, "profiles"),
                authorizations: list(&parsed, "auths"),
                roles: list(&parsed, "roles"),
                default_privileges: value(&parsed, "defaultpriv"),
                limit_privileges: value(&parsed, "limitpriv"),
                project: value(&parsed, "project"),
                attributes: attr.to_string(),
            },
        )
    })
}

#[derive(Serialize)]
struct Profile<'a> {
    /// `prof_attr`, `exec_attr` or `auth_attr`.
    table: &'static str,
    /// The profile (prof_attr, exec_attr) or authorization (auth_attr) name.
    name: &'a str,
    description: &'a str,
    /// exec_attr: the policy (`suser`, `solaris`) and kind (`cmd`, `act`).
    policy: &'a str,
    exec_type: &'a str,
    /// exec_attr: the command, or `*`.
    command: &'a str,
    /// prof_attr: the profiles it includes and authorizations it grants.
    profiles: Vec<String>,
    authorizations: Vec<String>,
    /// exec_attr: the command runs as root (`uid=0`, `euid=0`, or `privs=all`).
    runs_as_root: bool,
    attributes: String,
}

impl Record for Profile<'_> {}

fn parse_profiles(input: &Input, sink: &mut Sink) -> Result<()> {
    let table = if input.path.contains("exec_attr") {
        "exec_attr"
    } else if input.path.contains("auth_attr") {
        "auth_attr"
    } else {
        "prof_attr"
    };
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            return Ok(());
        }
        let fields = split_fields(text);
        let expected = match table {
            "exec_attr" => 7,
            "auth_attr" => 6,
            _ => 5,
        };
        if fields.len() != expected {
            sink.warn(format!("line {}: expected {expected} fields for {table}, found {}", line.number, fields.len()));
            return Ok(());
        }
        let attr = fields[expected - 1];
        let parsed = attrs(attr);
        let (description, policy, exec_type, command) = match table {
            "exec_attr" => ("", fields[1], fields[2], fields[5]),
            "auth_attr" => (fields[3], "", "", ""),
            _ => (fields[3], "", "", ""),
        };
        let runs_as_root = table == "exec_attr"
            && parsed.iter().any(|(k, v)| matches!((*k, v.as_str()), ("uid" | "euid", "0") | ("privs", "all")));
        sink.emit(
            Loc::Line(line.number),
            &Profile {
                table,
                name: fields[0],
                description,
                policy,
                exec_type,
                command,
                profiles: list(&parsed, "profiles"),
                authorizations: list(&parsed, "auths"),
                runs_as_root,
                attributes: attr.to_string(),
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    /// `profiles mallory` printed `Primary Administrator`, `Basic Solaris User`, `All`; `roles alice` printed `svcrole`.
    #[test]
    fn a_real_user_attr_equals_profiles_and_roles() {
        let out = run(&USER_ATTR, "etc/user_attr", &fixture("user-attr/user_attr"), 0);
        insta::assert_snapshot!(out);
        assert!(
            out.contains(
                r#""user":"mallory","qualifier":"","account_type":"normal","profiles":["Primary Administrator"]"#
            ),
            "{out}"
        );
        assert!(
            out.contains(r#""user":"svcrole""#)
                && out.contains(r#""account_type":"role","profiles":["Service Management"]"#),
            "{out}"
        );
        assert!(out.contains(r#""user":"alice""#) && out.contains(r#""roles":["svcrole"]"#), "{out}");
        assert!(String::from_utf8(fixture("user-attr/roles-alice.txt")).unwrap().trim() == "svcrole");
        assert!(String::from_utf8(fixture("user-attr/profiles-mallory.txt"))
            .unwrap()
            .contains("Primary Administrator"));
        // The escaped colon of `audit_flags=lo\:no` stays inside its attribute.
        assert!(out.contains(r#"audit_flags=lo\\:no"#), "{out}");
    }

    #[test]
    fn real_profile_files() {
        for (name, path) in [
            ("exec_attr", "etc/security/exec_attr"),
            ("prof_attr", "etc/security/prof_attr"),
            ("auth_attr", "etc/security/auth_attr"),
            ("exec_attr.d_nxmk", "etc/security/exec_attr.d/nxmk"),
            ("prof_attr.d_nxmk", "etc/security/prof_attr.d/nxmk"),
        ] {
            insta::assert_snapshot!(name, run(&RBAC, path, &fixture(&format!("rbac-profiles/{name}")), 0));
        }
        let out = run(&RBAC, "etc/security/exec_attr.d/nxmk", &fixture("rbac-profiles/exec_attr.d_nxmk"), 0);
        assert!(out.contains(r#""name":"NXMK_Profile","description":"","policy":"suser","exec_type":"cmd","command":"/tmp/.NXMK_EXECATTR/agent""#), "{out}");
        assert!(out.contains(r#""runs_as_root":true"#), "{out}");
    }

    #[test]
    fn escapes_and_odd_lines() {
        let out = run(&RBAC, "etc/security/exec_attr", b"P:suser:cmd:::/usr/bin/id:uid=0;gid=0\nQ:solaris:cmd:::/bin/x:privs=all\nR:solaris:cmd:::*:euid=0\nshort:line\n", 0);
        assert_eq!(out.matches("\"runs_as_root\":true").count(), 3, "{out}");
        assert!(out.contains("expected 7 fields for exec_attr, found 2"), "{out}");
        let out = run(&USER_ATTR, "etc/user_attr", b"u::::auths=a\\;b,c;profiles=P1,P2\nx:y\n", 0);
        assert!(out.contains(r#""authorizations":["a;b","c"]"#) && out.contains(r#""profiles":["P1","P2"]"#), "{out}");
        assert!(out.contains("expected 5 fields, found 2"), "{out}");
    }

    #[test]
    fn mutated_files_never_panic() {
        super::super::never_panics(&USER_ATTR, "etc/user_attr", &fixture("user-attr/user_attr"));
        super::super::never_panics(&RBAC, "etc/security/exec_attr", &fixture("rbac-profiles/exec_attr"));
    }
}
