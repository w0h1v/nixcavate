//! The `etc/security` stanza files as records: last logins, password ageing, user and group
//! attributes, limits, login and audit configuration. See [`super::stanza`] for the format and
//! its sources. Hashes in `etc/security/passwd` are never output: only the kind of hash.

use super::stanza::{for_each_stanza, read, Stanza};
use crate::{Artifact, Category, Input, AIX};
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::collections::BTreeMap;

pub const LASTLOG: Artifact = Artifact::new(
    "aix-lastlog",
    "AIX last successful and unsuccessful login per user",
    Category::Accounts,
    AIX,
    &["etc/security/lastlog"],
    parse_lastlog,
);
pub const PASSWD: Artifact = Artifact::new(
    "aix-security-passwd",
    "AIX password ageing and hash types (never the hashes)",
    Category::Accounts,
    AIX,
    &["etc/security/passwd", "etc/security/opasswd"],
    parse_passwd,
);
pub const USER: Artifact = Artifact::new(
    "aix-security-user",
    "AIX user attributes (login, rlogin, su, admin, locks, expiry)",
    Category::Accounts,
    AIX,
    &["etc/security/user"],
    parse_user,
);
pub const GROUP: Artifact = Artifact::new(
    "aix-security-group",
    "AIX group attributes (admin, administrators)",
    Category::Accounts,
    AIX,
    &["etc/security/group"],
    parse_group,
);
pub const CONFIG: Artifact = Artifact::new(
    "aix-security-config",
    "AIX security configuration stanzas (limits, login.cfg, environ, audit, SMIT ACLs, roles)",
    Category::Security,
    AIX,
    &[
        "etc/security/limits",
        "etc/security/login.cfg",
        "etc/security/environ",
        "etc/security/audit/config",
        "etc/security/smitacl.user",
        "etc/security/smitacl.group",
        "etc/security/roles",
        "etc/security/mkuser.default",
        "etc/security/mkuser.sys",
    ],
    parse_config,
);

fn epoch(value: Option<&str>) -> Option<Timestamp> {
    let secs: i64 = value?.trim().parse().ok()?;
    // 0 is "never"; negative and absurdly large values are not times.
    (1..=4_102_444_800).contains(&secs).then(|| Timestamp::from_secs(secs, Basis::Recorded))
}

// ---------------------------------------------------------------- lastlog

#[derive(Serialize)]
struct LastLogin<'a> {
    user: &'a str,
    last_login: Option<Timestamp>,
    last_login_tty: Option<&'a str>,
    last_login_host: Option<&'a str>,
    unsuccessful_login_count: Option<u32>,
    last_unsuccessful_login: Option<Timestamp>,
    last_unsuccessful_login_tty: Option<&'a str>,
    last_unsuccessful_login_host: Option<&'a str>,
}

impl Record for LastLogin<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let from = |tty: Option<&str>, host: Option<&str>| {
            format!(
                "{}{}",
                tty.map_or(String::new(), |t| format!(" on {t}")),
                host.map_or(String::new(), |h| format!(" from {h}"))
            )
        };
        let login = self.last_login.map(|ts| {
            Event::new(
                ts,
                "last_login",
                format!("last login of {}{}", self.user, from(self.last_login_tty, self.last_login_host)),
            )
        });
        let failed = self.last_unsuccessful_login.map(|ts| {
            Event::new(
                ts,
                "failed_login",
                format!(
                    "last unsuccessful login of {}{}",
                    self.user,
                    from(self.last_unsuccessful_login_tty, self.last_unsuccessful_login_host)
                ),
            )
        });
        login.into_iter().chain(failed)
    }
}

fn parse_lastlog(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = read(input, sink)?;
    for_each_stanza(&text, sink, |sink, s: Stanza| {
        let count = s.get("unsuccessful_login_count").and_then(|v| v.parse().ok());
        sink.emit(
            Loc::Line(s.line),
            &LastLogin {
                user: s.name,
                last_login: epoch(s.get("time_last_login")),
                last_login_tty: s.get("tty_last_login"),
                last_login_host: s.get("host_last_login"),
                unsuccessful_login_count: count,
                last_unsuccessful_login: epoch(s.get("time_last_unsuccessful_login")),
                last_unsuccessful_login_tty: s.get("tty_last_unsuccessful_login"),
                last_unsuccessful_login_host: s.get("host_last_unsuccessful_login"),
            },
        )
    })
}

// ---------------------------------------------------------------- passwd

#[derive(Serialize)]
struct Password<'a> {
    user: &'a str,
    /// `none` (`*`), `empty`, `des` (13 characters), `smd5`, `ssha1`, `ssha256`, `ssha512`
    /// (the `{...}` prefixes AIX writes), or `unknown`. `missing` when the stanza has no `password`.
    hash_type: &'static str,
    /// The `flags` attribute: `ADMCHG` (an administrator set it; the user must change it at the
    /// next login), `NOCHECK`, `ADMIN`.
    flags: Vec<&'a str>,
    last_update: Option<Timestamp>,
}

impl Record for Password<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.last_update
            .map(|ts| Event::new(ts, "password_changed", format!("password of {} changed", self.user)))
            .into_iter()
    }
}

fn hash_type(password: Option<&str>) -> &'static str {
    match password {
        None => "missing",
        Some("") => "empty",
        Some("*") => "none",
        Some(p) if p.starts_with("{smd5}") => "smd5",
        Some(p) if p.starts_with("{ssha1}") => "ssha1",
        Some(p) if p.starts_with("{ssha256}") => "ssha256",
        Some(p) if p.starts_with("{ssha512}") => "ssha512",
        Some(p) if p.len() == 13 => "des",
        Some(_) => "unknown",
    }
}

fn parse_passwd(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = read(input, sink)?;
    for_each_stanza(&text, sink, |sink, s: Stanza| {
        let flags = s.get("flags").map(|f| f.split([',', ' ']).filter(|p| !p.is_empty()).collect()).unwrap_or_default();
        sink.emit(
            Loc::Line(s.line),
            &Password {
                user: s.name,
                hash_type: hash_type(s.get("password")),
                flags,
                last_update: epoch(s.get("lastupdate")),
            },
        )
    })
}

// ---------------------------------------------------------------- user

#[derive(Serialize)]
struct UserAttributes<'a> {
    user: &'a str,
    admin: Option<&'a str>,
    login: Option<&'a str>,
    rlogin: Option<&'a str>,
    su: Option<&'a str>,
    sugroups: Option<&'a str>,
    account_locked: Option<&'a str>,
    /// `MMDDhhmmyy` as AIX stores it; `0` means never.
    expires: Option<&'a str>,
    ttys: Option<&'a str>,
    auth1: Option<&'a str>,
    registry: Option<&'a str>,
    system: Option<&'a str>,
    daemon: Option<&'a str>,
    attributes: BTreeMap<&'a str, &'a str>,
}

impl Record for UserAttributes<'_> {}

fn parse_user(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = read(input, sink)?;
    for_each_stanza(&text, sink, |sink, s: Stanza| {
        sink.emit(
            Loc::Line(s.line),
            &UserAttributes {
                user: s.name,
                admin: s.get("admin"),
                login: s.get("login"),
                rlogin: s.get("rlogin"),
                su: s.get("su"),
                sugroups: s.get("sugroups"),
                account_locked: s.get("account_locked"),
                expires: s.get("expires"),
                ttys: s.get("ttys"),
                auth1: s.get("auth1"),
                registry: s.get("registry"),
                system: s.get("SYSTEM"),
                daemon: s.get("daemon"),
                attributes: s.attributes.clone(),
            },
        )
    })
}

// ---------------------------------------------------------------- group

#[derive(Serialize)]
struct GroupAttributes<'a> {
    group: &'a str,
    id: Option<u32>,
    admin: Option<&'a str>,
    /// Users who administer the group.
    adms: Vec<&'a str>,
    users: Vec<&'a str>,
    attributes: BTreeMap<&'a str, &'a str>,
}

impl Record for GroupAttributes<'_> {}

fn parse_group(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = read(input, sink)?;
    for_each_stanza(&text, sink, |sink, s: Stanza| {
        let list = |key: &str| -> Vec<&str> {
            s.get(key).map(|v| v.split(',').map(str::trim).filter(|p| !p.is_empty()).collect()).unwrap_or_default()
        };
        sink.emit(
            Loc::Line(s.line),
            &GroupAttributes {
                group: s.name,
                id: s.get("id").and_then(|v| v.parse().ok()),
                admin: s.get("admin"),
                adms: list("adms"),
                users: list("users"),
                attributes: s.attributes.clone(),
            },
        )
    })
}

// ---------------------------------------------------------------- config

#[derive(Serialize)]
struct ConfigStanza<'a> {
    /// The file's name: `limits`, `login.cfg`, `config` (audit), ...
    file: &'a str,
    stanza: &'a str,
    attributes: BTreeMap<&'a str, &'a str>,
}

impl Record for ConfigStanza<'_> {}

fn parse_config(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = read(input, sink)?;
    let file = input.path.rsplit('/').next().unwrap_or(input.path);
    for_each_stanza(&text, sink, |sink, s: Stanza| {
        sink.emit(Loc::Line(s.line), &ConfigStanza { file, stanza: s.name, attributes: s.attributes.clone() })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;

    const LASTLOG_TEXT: &[u8] = b"alice:\n\ttime_last_login = 1710032400\n\ttty_last_login = /dev/pts/0\n\thost_last_login = 203.0.113.9\n\tunsuccessful_login_count = 2\n\ttime_last_unsuccessful_login = 1710032000\n\ttty_last_unsuccessful_login = ssh\n\thost_last_unsuccessful_login = 198.51.100.4\n\nbob:\n\tunsuccessful_login_count = 0\n";

    #[test]
    fn lastlog_records_and_events() {
        insta::assert_snapshot!(run(&LASTLOG, "etc/security/lastlog", LASTLOG_TEXT, 0));
    }

    #[test]
    fn passwd_keeps_only_the_hash_kind() {
        let text = b"* comment\nroot:\n\tpassword = {ssha256}12$abcdefSECRET$xyz\n\tlastupdate = 1700000000\n\tflags = ADMCHG,NOCHECK\n\nold:\n\tpassword = abcdefghijklm\n\nlocked:\n\tpassword = *\n\nodd:\n\tpassword = something else\n";
        let out = run(&PASSWD, "etc/security/passwd", text, 0);
        assert!(!out.contains("SECRET") && !out.contains("abcdefghijklm"), "{out}");
        for kind in ["ssha256", "des", "none", "unknown"] {
            assert!(out.contains(&format!("\"hash_type\":\"{kind}\"")), "{kind}: {out}");
        }
        assert!(out.contains("password of root changed"), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn user_attributes() {
        let text = b"default:\n\tadmin = false\n\tlogin = true\n\trlogin = true\n\tsu = true\n\nroot:\n\tadmin = true\n\trlogin = false\n\tSYSTEM = \"compat\"\n\tloginretries = 0\n\nmallory:\n\tshell stuff\n";
        let out = run(&USER, "etc/security/user", text, 0);
        assert!(
            out.contains(r#""system":"compat""#) && out.contains("neither a stanza header nor an attribute"),
            "{out}"
        );
        insta::assert_snapshot!(out);
    }

    #[test]
    fn group_and_config() {
        let out = run(&GROUP, "etc/security/group", b"system:\n\tadmin = true\n\tadms = root,alice\n", 0);
        assert!(out.contains(r#""adms":["root","alice"]"#), "{out}");
        let out = run(&CONFIG, "etc/security/limits", b"default:\n\tfsize = 2097151\n\tcore = 2097151\n", 0);
        assert!(out.contains(r#""file":"limits","stanza":"default""#), "{out}");
    }

    #[test]
    fn hostile_inputs() {
        for data in [&b""[..], b"\0\0\0", b"\xff\xfe:\n\t= =\n=\n:\n", b"a:\nb = c\n", &[b'x'; 100_000][..]] {
            for artifact in [&LASTLOG, &PASSWD, &USER, &GROUP, &CONFIG] {
                let _ = run(artifact, "etc/security/user", data, 0);
            }
        }
        let many: String = (0..2000).map(|i| format!("\tk{i} = v\n")).collect();
        let out = run(&USER, "etc/security/user", format!("u:\n{many}").as_bytes(), 0);
        assert!(out.contains("attributes beyond 512"), "{}", &out[out.len().saturating_sub(300)..]);
    }
}
