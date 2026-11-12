//! `auth.log` (Debian) and `secure` (Red Hat): authentication and account events. The message
//! texts come from OpenSSH (`auth.c`, `sshd.c`), sudo(8), su, Linux-PAM's `pam_unix` and
//! shadow-utils. Header layouts: `common::syslog`.
//!
//! On systems whose syslogd sends auth events to `messages` (Alpine's BusyBox syslogd, SUSE),
//! that file is read too, and only its lines that are auth events become records here: the
//! `syslog` artifact already has every line.

use crate::common::syslog::{for_each_header, timeline_message};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "auth-log",
    "Authentication events: ssh, sudo, su, PAM sessions, account changes",
    Category::Logs,
    LINUX,
    &["var/log/auth.log*", "var/log/secure*", "var/log/messages*"],
    parse,
)
.split_lines();

/// What a recognised message says. Empty strings and `None` mean "not applicable". For group
/// events `user` holds the group name; for `su` and `sudo`, `user` is who ran the command and
/// `run_as` the account it ran as.
#[derive(Default)]
struct Auth<'a> {
    event: &'static str,
    user: &'a str,
    remote_address: &'a str,
    remote_port: Option<u16>,
    method: &'a str,
    key_fingerprint: &'a str,
    command: &'a str,
    run_as: &'a str,
    cwd: &'a str,
    tty: &'a str,
}

#[derive(Serialize)]
struct Entry<'a> {
    time: Option<Timestamp>,
    time_basis: Option<Basis>,
    log_host: &'a str,
    program: &'a str,
    pid: Option<u32>,
    message: &'a str,
    event: &'static str,
    user: &'a str,
    remote_address: &'a str,
    remote_port: Option<u16>,
    method: &'a str,
    key_fingerprint: &'a str,
    command: &'a str,
    run_as: &'a str,
    cwd: &'a str,
    tty: &'a str,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who = if self.user.is_empty() { "unknown user" } else { self.user };
        let from =
            if self.remote_address.is_empty() { String::new() } else { format!(" from {}", self.remote_address) };
        let text = match self.event {
            "" => {
                return self
                    .time
                    .map(|ts| Event::new(ts, "log", timeline_message(self.program, self.message)))
                    .into_iter()
            }
            "ssh_accepted" => format!("{who} logged in via ssh ({}){from}", self.method),
            "ssh_failed" => format!("failed ssh login for {who} ({}){from}", self.method),
            "ssh_invalid_user" => format!("ssh login attempt for invalid user {who}{from}"),
            "ssh_disconnect" => format!("ssh disconnect of {who}{from}"),
            "ssh_connection_closed" => format!("ssh connection closed{from}"),
            "session_opened" => format!("session opened for {who} ({})", self.program),
            "session_closed" => format!("session closed for {who} ({})", self.program),
            "sudo_command" => format!("{who} ran {} as {}", self.command, self.run_as),
            "sudo_failure" => format!("sudo refused {who}: {} as {}", self.command, self.run_as),
            "su" if self.message.starts_with("FAILED") => format!("failed su to {} by {who}", self.run_as),
            "su" => format!("{who} su to {}", self.run_as),
            "account_created" => format!("account {who} created"),
            "account_deleted" => format!("account {who} deleted"),
            "group_created" => format!("group {who} created"),
            _ => format!("password changed for {who}"),
        };
        self.time.map(|ts| Event::new(ts, self.event, text)).into_iter()
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mixed = input.path.rsplit('/').next().is_some_and(|name| name.starts_with("messages"));
    for_each_header(input, |offset, h| {
        let a = classify(&h.program, &h.message).unwrap_or_default();
        if mixed && a.event.is_empty() {
            return Ok(());
        }
        sink.emit(
            Loc::Offset(offset),
            &Entry {
                time: h.time,
                time_basis: h.time.map(|t| t.basis),
                log_host: &h.log_host,
                program: &h.program,
                pid: h.pid,
                message: &h.message,
                event: a.event,
                user: a.user,
                remote_address: a.remote_address,
                remote_port: a.remote_port,
                method: a.method,
                key_fingerprint: a.key_fingerprint,
                command: a.command,
                run_as: a.run_as,
                cwd: a.cwd,
                tty: a.tty,
            },
        )
    })
}

fn classify<'a>(program: &str, message: &'a str) -> Option<Auth<'a>> {
    let msg = message.trim_start();
    // sshd became sshd-session in OpenSSH 9.8.
    let by_program = match program {
        p if p.starts_with("sshd") => ssh(msg),
        "sudo" => sudo(msg),
        "su" => su(msg),
        "useradd" | "groupadd" | "userdel" => shadow_utils(program, msg),
        "passwd" => passwd(msg),
        _ => None,
    };
    by_program.or_else(|| pam_unix(msg))
}

fn word_after<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    let rest = &text[text.find(marker)? + marker.len()..];
    rest.split([' ', ',', ')']).next()
}

fn port_prefix(token: &str) -> Option<u16> {
    let digits = token.bytes().take_while(u8::is_ascii_digit).count();
    token[..digits].parse().ok()
}

fn ssh(msg: &str) -> Option<Auth<'_>> {
    let accepted = msg.strip_prefix("Accepted ");
    if let Some(rest) = accepted.or_else(|| msg.strip_prefix("Failed ")) {
        // `METHOD for [invalid user ]USER from ADDRESS port PORT ssh2[: KEYTYPE SHA256:...]`.
        // A user name is chosen by the client and may hold ` from ` and ` port `, so the
        // address and port are the LAST such pair, and the fingerprint is read only after them.
        let (head, tail) = rest.rsplit_once(" from ")?;
        let (method, head) = head.split_once(" for ")?;
        let user = head.strip_prefix("invalid user ").unwrap_or(head);
        let mut w = tail.splitn(4, ' ');
        let remote_address = w.next()?;
        (w.next()? == "port").then_some(())?;
        let remote_port = port_prefix(w.next()?);
        return Some(Auth {
            event: if accepted.is_some() { "ssh_accepted" } else { "ssh_failed" },
            user,
            remote_address,
            remote_port,
            method,
            key_fingerprint: fingerprint(w.next().unwrap_or_default()),
            ..Auth::default()
        });
    }
    if let Some(rest) = msg.strip_prefix("Invalid user ") {
        // `USER from ADDRESS[ port PORT]`; the user name may itself contain ` from `.
        let (user, tail) = rest.rsplit_once(" from ")?;
        let mut w = tail.split(' ');
        let remote_address = w.next()?;
        let remote_port = (w.next() == Some("port")).then(|| w.next().and_then(port_prefix)).flatten();
        return Some(Auth { event: "ssh_invalid_user", user, remote_address, remote_port, ..Auth::default() });
    }
    if let Some(rest) = msg.strip_prefix("input_userauth_request: invalid user ") {
        return Some(Auth { event: "ssh_invalid_user", user: rest.split(' ').next()?, ..Auth::default() });
    }
    let (event, rest) = [
        ("ssh_disconnect", "Disconnected from "),
        ("ssh_disconnect", "Received disconnect from "),
        ("ssh_disconnect", "Disconnecting "),
        ("ssh_connection_closed", "Connection closed by "),
        ("ssh_connection_closed", "Connection reset by "),
    ]
    .into_iter()
    .find_map(|(event, prefix)| Some((event, msg.strip_prefix(prefix)?)))?;
    peer(event, rest)
}

/// The `SHA256:...` token of a key fingerprint.
fn fingerprint(text: &str) -> &str {
    text.find("SHA256:").map_or("", |i| text[i..].split(' ').next().unwrap_or_default())
}

/// OpenSSH's description of the other end of a connection: `[authenticating user |invalid
/// user |user USER ]ADDRESS port PORT`, followed by `:` or `[preauth]` text. Old versions
/// write `ADDRESS:` with no port.
fn peer<'a>(event: &'static str, mut rest: &'a str) -> Option<Auth<'a>> {
    let mut user = "";
    for prefix in ["authenticating user ", "invalid user ", "user "] {
        if let Some(after) = rest.strip_prefix(prefix) {
            // The user name is client-chosen and may hold spaces: the address and port are the
            // last pair, and the name is what precedes the address.
            let right = after.rsplit_once(" port ").and_then(|(head, tail)| Some((head.rsplit_once(' ')?, tail)));
            if let Some(((user, remote_address), tail)) = right {
                return Some(Auth { event, user, remote_address, remote_port: port_prefix(tail), ..Auth::default() });
            }
            (user, rest) = after.split_once(' ')?;
            break;
        }
    }
    let mut w = rest.split(' ');
    let remote_address = w.next()?.trim_end_matches(':');
    let remote_port = (w.next() == Some("port")).then(|| w.next().and_then(port_prefix)).flatten();
    Some(Auth { event, user, remote_address, remote_port, ..Auth::default() })
}

/// `USER : [3 incorrect password attempts ; ]TTY=pts/0 ; PWD=/home/u ; USER=root ; COMMAND=...`.
/// Text before the key=value fields that is not itself a field (`user NOT in sudoers`) is a
/// refusal.
fn sudo(msg: &str) -> Option<Auth<'_>> {
    let (user, rest) = msg.split_once(" : ")?;
    let at = rest.find("COMMAND=")?;
    let mut a = Auth { event: "sudo_command", user, command: &rest[at + "COMMAND=".len()..], ..Auth::default() };
    // Only text before the first TTY/PWD/USER field can be a refusal; later ` ; ` may come from
    // a directory name.
    let mut in_fields = false;
    for part in rest[..at].split(" ; ").map(str::trim).filter(|p| !p.is_empty()) {
        match part.split_once('=') {
            Some(("TTY", v)) => (in_fields, a.tty) = (true, v),
            Some(("PWD", v)) => (in_fields, a.cwd) = (true, v),
            Some(("USER", v)) => (in_fields, a.run_as) = (true, v),
            Some((key, _)) if key.bytes().all(|b| b.is_ascii_uppercase()) => {}
            _ if !in_fields => a.event = "sudo_failure",
            _ => {}
        }
    }
    Some(a)
}

/// `(to root) alice on pts/0`, `FAILED SU (to root) alice on pts/0` (util-linux), and
/// `Successful su for root by alice` / `FAILED su for root by alice` (shadow).
fn su(msg: &str) -> Option<Auth<'_>> {
    let msg = msg.strip_prefix("FAILED SU ").unwrap_or(msg);
    if let Some(rest) = msg.strip_prefix("(to ") {
        let (run_as, rest) = rest.split_once(") ")?;
        let (user, tty) = rest.split_once(" on ")?;
        return Some(Auth { event: "su", user, run_as, tty, ..Auth::default() });
    }
    let rest = msg.strip_prefix("Successful su for ").or_else(|| msg.strip_prefix("FAILED su for "))?;
    let (run_as, user) = rest.split_once(" by ")?;
    Some(Auth { event: "su", user, run_as, ..Auth::default() })
}

fn shadow_utils<'a>(program: &str, msg: &'a str) -> Option<Auth<'a>> {
    let (event, name) = match program {
        "useradd" if msg.starts_with("new user: ") => ("account_created", word_after(msg, "name=")?),
        "useradd" | "groupadd" if msg.starts_with("new group: ") => ("group_created", word_after(msg, "name=")?),
        "userdel" if msg.starts_with("delete user '") => ("account_deleted", quoted(msg)?),
        _ => return None,
    };
    Some(Auth { event, user: name, ..Auth::default() })
}

fn quoted(text: &str) -> Option<&str> {
    text.split('\'').nth(1)
}

/// `passwd: password for 'alice' changed by 'root'`.
fn passwd(msg: &str) -> Option<Auth<'_>> {
    msg.starts_with("password for '").then(|| Auth {
        event: "password_changed",
        user: quoted(msg).unwrap_or(""),
        ..Auth::default()
    })
}

/// `pam_unix(SERVICE:session): session opened for user alice(uid=1000) by (uid=0)` and
/// `pam_unix(passwd:chauthtok): password changed for alice`.
fn pam_unix(msg: &str) -> Option<Auth<'_>> {
    let rest = msg.strip_prefix("pam_unix(")?;
    let (_, text) = rest.split_once("): ")?;
    let (event, tail) = if let Some(t) = text.strip_prefix("session opened for user ") {
        ("session_opened", t)
    } else if let Some(t) = text.strip_prefix("session closed for user ") {
        ("session_closed", t)
    } else {
        ("password_changed", text.strip_prefix("password changed for ")?)
    };
    let user = tail.split([' ', '(']).next()?;
    Some(Auth { event, user, ..Auth::default() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};
    use std::io::Write;

    const NOV_12_2026: i64 = 1_794_441_600;
    const MAR_10_2024: i64 = 1_710_028_800;

    fn parsed(line: &str) -> serde_json::Value {
        let out = run(&ARTIFACT, "var/log/auth.log", line.as_bytes(), MAR_10_2024);
        serde_json::from_str(out.lines().next().unwrap()).unwrap()
    }

    /// Alpine's BusyBox syslogd and SUSE's rsyslog write auth events to `messages`, between
    /// everything else. Only the lines that are auth events become records there.
    #[test]
    fn auth_events_in_messages_are_picked_out() {
        let log = "Mar  9 01:02:03 web01 auth.info sshd-session[89]: Accepted publickey for alice from 203.0.113.9 port 60102 ssh2: ED25519 SHA256:abc\n\
                   Mar  9 01:02:04 web01 daemon.info crond[7]: USER root pid 9 cmd run-parts /etc/periodic/15min\n\
                   2024-03-09T01:02:05.000000+00:00 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id\n\
                   2024-03-09T01:02:06.000000+00:00 web01 kernel: [    0.000000] Linux version 6.4\n";
        let out = run(&ARTIFACT, "var/log/messages", log.as_bytes(), MAR_10_2024);
        let records: Vec<serde_json::Value> =
            out.lines().filter(|l| l.starts_with('{')).map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(records.len(), 2, "{out}");
        assert_eq!((records[0]["event"].as_str(), records[0]["user"].as_str()), (Some("ssh_accepted"), Some("alice")));
        assert_eq!(records[0]["program"], "sshd-session");
        assert_eq!(
            (records[1]["event"].as_str(), records[1]["command"].as_str()),
            (Some("sudo_command"), Some("/usr/bin/id"))
        );
        // In auth.log every line is a record, classified or not.
        let out = run(&ARTIFACT, "var/log/auth.log", log.as_bytes(), MAR_10_2024);
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 4, "{out}");
    }

    #[test]
    fn invalid_user_name_cannot_spoof_the_address() {
        let v = parsed("Mar  9 01:02:03 web01 sshd[1]: Failed password for invalid user x from 6.6.6.6 port 1 from 10.9.9.9 port 4242 ssh2\n");
        assert_eq!(
            (v["user"].as_str(), v["remote_address"].as_str(), v["remote_port"].as_u64()),
            (Some("x from 6.6.6.6 port 1"), Some("10.9.9.9"), Some(4242))
        );
        let v = parsed(
            "Mar  9 01:02:04 web01 sshd[1]: Invalid user SHA256:fake from 7.7.7.7 port 1 from 10.9.9.9 port 4243\n",
        );
        assert_eq!(
            (v["remote_address"].as_str(), v["remote_port"].as_u64(), v["key_fingerprint"].as_str()),
            (Some("10.9.9.9"), Some(4243), Some(""))
        );
        let v = parsed("Mar  9 01:02:05 web01 sshd[1]: Failed password for invalid user SHA256:fake from 10.9.9.9 port 4244 ssh2\n");
        assert_eq!(v["key_fingerprint"].as_str(), Some(""));
        let v = parsed("Mar  9 01:02:06 web01 sshd[1]: Accepted publickey for alice from 10.9.9.9 port 4245 ssh2: ED25519 SHA256:real\n");
        assert_eq!((v["user"].as_str(), v["key_fingerprint"].as_str()), (Some("alice"), Some("SHA256:real")));
    }

    #[test]
    fn disconnect_with_a_spaced_user_name_takes_the_last_address() {
        let v = parsed("Mar  9 01:02:03 web01 sshd[1]: Disconnected from invalid user bob from 6.6.6.6 port 1 10.9.9.9 port 4242 [preauth]\n");
        assert_eq!(
            (v["user"].as_str(), v["remote_address"].as_str(), v["remote_port"].as_u64()),
            (Some("bob from 6.6.6.6 port 1"), Some("10.9.9.9"), Some(4242))
        );
    }

    #[test]
    fn sudo_pwd_with_separator_stays_a_success() {
        let v =
            parsed("Mar  9 01:02:03 web01 sudo:    alice : TTY=pts/0 ; PWD=/tmp/a ; b ; USER=root ; COMMAND=/bin/id\n");
        assert_eq!(v["event"].as_str(), Some("sudo_command"));
        let v = parsed("Mar  9 01:02:03 web01 sudo:    alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/id\n");
        assert_eq!(v["event"].as_str(), Some("sudo_failure"));
    }

    #[test]
    fn debian_auth_log() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/auth.log", &fixture("auth-log/auth.log"), NOV_12_2026));
    }

    #[test]
    fn rocky_secure() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/secure", &fixture("auth-log/secure"), NOV_12_2026));
    }

    #[test]
    fn classic_layout() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/auth.log", &fixture("auth-log/auth_classic.log"), NOV_12_2026));
    }

    #[test]
    fn openssh_and_sudo_variants() {
        insta::assert_snapshot!(run(
            &ARTIFACT,
            "var/log/auth.log.1",
            &fixture("auth-log/openssh_variants.log"),
            MAR_10_2024
        ));
    }

    #[test]
    fn gzip_rotation_matches_plain() {
        let plain = fixture("auth-log/openssh_variants.log");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&plain).unwrap();
        let packed = gz.finish().unwrap();
        let from_gz = run(&ARTIFACT, "var/log/auth.log.2.gz", &packed, MAR_10_2024);
        assert_eq!(
            from_gz.replace("auth.log.2.gz", "auth.log.1"),
            run(&ARTIFACT, "var/log/auth.log.1", &plain, MAR_10_2024)
        );
    }

    #[test]
    fn every_event_is_covered_by_the_fixtures() {
        let mut seen = std::collections::BTreeSet::new();
        for name in ["auth-log/auth.log", "auth-log/secure", "auth-log/openssh_variants.log"] {
            let out = run(&ARTIFACT, "var/log/auth.log", &fixture(name), NOV_12_2026);
            seen.extend(
                out.lines().filter_map(|l| l.split("\"event\":\"").nth(1)?.split('"').next().map(String::from)),
            );
        }
        for event in [
            "ssh_accepted",
            "ssh_failed",
            "ssh_invalid_user",
            "ssh_disconnect",
            "ssh_connection_closed",
            "session_opened",
            "session_closed",
            "sudo_command",
            "sudo_failure",
            "su",
            "account_created",
            "account_deleted",
            "group_created",
            "password_changed",
        ] {
            assert!(seen.contains(event), "no fixture line for {event}");
        }
    }

    #[test]
    fn garbage_and_empty_input() {
        let data = b"\x00\xff\xfe\nsshd[1]: Accepted\nMar  9 01:02:03 web01 sshd[1]: Accepted publickey for\nMar  9 01:02:03 web01 sudo: : COMMAND=\nMar  9 01:02:03 web01 su: (to \nMar  9 01:02:03 web01 pam_unix(x): \nMar  9 01:02:03 web01 passwd: password for '\n";
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/auth.log", data, MAR_10_2024));
        assert_eq!(run(&ARTIFACT, "var/log/auth.log", b"", MAR_10_2024), "");
    }

    #[test]
    fn truncated_and_corrupted_input_never_panics() {
        for name in ["auth-log/auth.log", "auth-log/openssh_variants.log"] {
            let data = fixture(name);
            for len in (0..data.len()).step_by(7) {
                run(&ARTIFACT, "var/log/auth.log", &data[..len], MAR_10_2024);
            }
            for i in (0..data.len()).step_by(11) {
                let mut flipped = data.clone();
                flipped[i] ^= 0x5a;
                run(&ARTIFACT, "var/log/auth.log", &flipped, MAR_10_2024);
            }
        }
    }
}
