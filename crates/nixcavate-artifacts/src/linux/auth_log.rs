//! `auth.log` (Debian) and `secure` (Red Hat): authentication and account events. The message
//! texts come from OpenSSH (`auth.c`, `sshd.c`), sudo(8), su, Linux-PAM's `pam_unix` (also in
//! its old form, with the module named in the program: `sshd(pam_unix)`) and
//! shadow-utils. Header layouts: `common::syslog`.
//!
//! On systems whose syslogd sends auth events to `messages` (Alpine's BusyBox syslogd, SUSE),
//! that file is read too, and only its lines that are auth events become records here: the
//! `syslog` artifact already has every line.

use crate::common::syslog::{for_each_header, timeline_message};
use crate::{Artifact, Category, Input, UNIX_NOT_ESXI};
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "auth-log",
    "Authentication events: ssh, sudo, su, PAM sessions, account changes",
    Category::Logs,
    UNIX_NOT_ESXI,
    &["var/log/auth.log*", "var/log/secure*", "var/log/messages*", "var/adm/messages*", "var/log/authlog*"],
    parse,
)
.split_lines();

/// What a recognised message says. Empty strings and `None` mean "not applicable". For group
/// events `user` holds the group name; for `su` and `sudo`, `user` is who ran the command and
/// `run_as` the account it ran as.
#[derive(Default)]
pub(crate) struct Auth<'a> {
    pub(crate) event: &'static str,
    pub(crate) user: &'a str,
    pub(crate) remote_address: &'a str,
    pub(crate) remote_port: Option<u16>,
    pub(crate) method: &'a str,
    pub(crate) key_fingerprint: &'a str,
    pub(crate) command: &'a str,
    pub(crate) run_as: &'a str,
    pub(crate) cwd: &'a str,
    pub(crate) tty: &'a str,
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
        if self.event.is_empty() {
            return self.time.map(|ts| Event::new(ts, "log", timeline_message(self.program, self.message))).into_iter();
        }
        let auth = Auth {
            event: self.event,
            user: self.user,
            remote_address: self.remote_address,
            method: self.method,
            command: self.command,
            run_as: self.run_as,
            ..Auth::default()
        };
        self.time.map(|ts| Event::new(ts, self.event, auth.describe(self.program, self.message))).into_iter()
    }
}

impl Auth<'_> {
    /// The timeline text of a classified event.
    pub(crate) fn describe(&self, program: &str, message: &str) -> String {
        let who = if self.user.is_empty() { "unknown user" } else { self.user };
        let from =
            if self.remote_address.is_empty() { String::new() } else { format!(" from {}", self.remote_address) };
        match self.event {
            "ssh_accepted" => format!("{who} logged in via ssh ({}){from}", self.method),
            "ssh_failed" => format!("failed ssh login for {who} ({}){from}", self.method),
            "ssh_invalid_user" => format!("ssh login attempt for invalid user {who}{from}"),
            "ssh_disconnect" => format!("ssh disconnect of {who}{from}"),
            "ssh_connection_closed" => format!("ssh connection closed{from}"),
            "auth_failure" => format!("authentication failure for {who} ({program}){from}"),
            "session_opened" => format!("session opened for {who} ({program})"),
            "session_closed" => format!("session closed for {who} ({program})"),
            "sudo_command" => format!("{who} ran {} as {}", self.command, self.run_as),
            "sudo_failure" => format!("sudo refused {who}: {} as {}", self.command, self.run_as),
            "su" if message.trim_start().starts_with("FAILED")
                || message.trim_start().starts_with("BAD SU")
                || message.contains("' failed for ") =>
            {
                format!("failed su to {} by {who}", self.run_as)
            }
            "su" => format!("{who} su to {}", self.run_as),
            "account_created" => format!("account {who} created"),
            "account_deleted" => format!("account {who} deleted"),
            "group_created" => format!("group {who} created"),
            "group_member_added" => message.trim().to_string(),
            "account_modified" => format!("account {who} modified"),
            "group_deleted" => format!("group {who} deleted"),
            "login" => format!("{who} logged in on {} (login)", self.tty),
            _ => format!("password changed for {who}"),
        }
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

/// Solaris and illumos syslog puts `[ID 800047 auth.info] ` in front of every message: a message
/// id and the facility and level. It is not part of the message and hides its start.
fn without_message_id(msg: &str) -> &str {
    let Some(rest) = msg.strip_prefix("[ID ") else { return msg };
    match rest.split_once("] ") {
        Some((id, tail)) if id.len() <= 32 && id.split(' ').count() == 2 => tail,
        _ => msg,
    }
}

pub(crate) fn classify<'a>(program: &str, message: &'a str) -> Option<Auth<'a>> {
    let msg = without_message_id(message.trim_start());
    // rsyslog folds identical lines: `message repeated N times: [ TEXT]`.
    let repeated =
        msg.strip_prefix("message repeated ").and_then(|rest| rest.split_once(" times: [")?.1.strip_suffix(']'));
    let msg = repeated.map_or(msg, str::trim_start);
    // PAM before 0.99 names the module in the program, `sshd(pam_unix)`, not in the message.
    if let Some(program) = program.strip_suffix("(pam_unix)") {
        return classify(program, msg).or_else(|| pam_text(msg));
    }
    // sshd became sshd-session in OpenSSH 9.8.
    let by_program = match program {
        p if p.starts_with("sshd") => ssh(msg),
        "sudo" => sudo(msg),
        "su" => su(msg),
        // The Solaris repeated-failure line first: the BSD failure rule would also take it.
        "login" if msg.starts_with("REPEATED LOGIN FAILURES ON ") => solaris_login(msg),
        "login" => bsd_login(msg).or_else(|| solaris_login(msg)),
        "doas" => doas(msg),
        "useradd" | "groupadd" | "userdel" | "usermod" | "gpasswd" => {
            shadow_utils(program, msg).or_else(|| bsd_account(msg))
        }
        "groupdel" | "groupmod" => bsd_account(msg),
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

/// Solaris `login`: `REPEATED LOGIN FAILURES ON /dev/pts/1, mallory` and `ROOT LOGIN /dev/console`.
fn solaris_login(msg: &str) -> Option<Auth<'_>> {
    if let Some(rest) = msg.strip_prefix("REPEATED LOGIN FAILURES ON ") {
        let (tty, user) = rest.split_once(',').unwrap_or((rest, ""));
        return Some(Auth {
            event: "auth_failure",
            user: user.trim(),
            tty: tty.trim().trim_start_matches("/dev/"),
            ..Auth::default()
        });
    }
    let tty = msg.strip_prefix("ROOT LOGIN ")?;
    Some(Auth { event: "session_opened", user: "root", tty: tty.trim().trim_start_matches("/dev/"), ..Auth::default() })
}

/// `(to root) alice on pts/0`, `FAILED SU (to root) alice on pts/0` (util-linux), and
/// `Successful su for root by alice` / `FAILED su for root by alice` (shadow); on Solaris
/// `'su root' succeeded for alice on /dev/pts/1` and `'su root' failed for alice on /dev/pts/1`.
fn su(msg: &str) -> Option<Auth<'_>> {
    if let Some(rest) = msg.strip_prefix("'su") {
        let (target, rest) = rest.split_once("' ")?;
        let rest = rest.strip_prefix("succeeded for ").or_else(|| rest.strip_prefix("failed for "))?;
        let (user, tty) = rest.split_once(" on ")?;
        // `su -` and `su - alice` name no account, or the account after the flag.
        let run_as = target.split_whitespace().rfind(|w| !w.starts_with('-')).unwrap_or("root");
        return Some(Auth { event: "su", user, run_as, tty: tty.trim_start_matches("/dev/"), ..Auth::default() });
    }
    let msg = msg.strip_prefix("FAILED SU ").unwrap_or(msg);
    if let Some(rest) = msg.strip_prefix("(to ") {
        let (run_as, rest) = rest.split_once(") ")?;
        let (user, tty) = rest.split_once(" on ")?;
        return Some(Auth { event: "su", user, run_as, tty, ..Auth::default() });
    }
    if let Some(rest) = msg.strip_prefix("Successful su for ").or_else(|| msg.strip_prefix("FAILED su for ")) {
        let (run_as, user) = rest.split_once(" by ")?;
        return Some(Auth { event: "su", user, run_as, ..Auth::default() });
    }
    // BSD su: `alice to root on /dev/pts/0` and `BAD SU alice to bob on /dev/pts/0`.
    // Both names are single words and the terminal is always given, so a PAM message that
    // happens to hold " to " and " on " (`pam_systemd(su:session): Failed to connect ...`) is not one.
    let rest = msg.strip_prefix("BAD SU ").unwrap_or(msg);
    let (user, rest) = rest.split_once(" to ")?;
    let (run_as, tty) = rest.split_once(" on ")?;
    let word = |w: &str| !w.is_empty() && !w.contains([' ', ':', '(', ')']);
    (word(user) && word(run_as) && tty.starts_with("/dev/")).then_some(Auth {
        event: "su",
        user,
        run_as,
        tty,
        ..Auth::default()
    })
}

/// OpenBSD and NetBSD `useradd(8)` and friends log `new user added: name=NAME, uid=...` (NetBSD
/// capitalizes the first word), `user information modified: name=...`, `user removed: name=...`,
/// `new group added: name=...` and `group deleted: name=...`.
fn bsd_account(msg: &str) -> Option<Auth<'_>> {
    let lower = msg.to_ascii_lowercase();
    let event = if lower.starts_with("new user added: ") {
        "account_created"
    } else if lower.starts_with("user information modified: ") {
        "account_modified"
    } else if lower.starts_with("user removed: ") {
        "account_deleted"
    } else if lower.starts_with("new group added: ") {
        "group_created"
    } else if lower.starts_with("group deleted: ") {
        "group_deleted"
    } else {
        return None;
    };
    Some(Auth { event, user: word_after(msg, "name=")?, ..Auth::default() })
}

/// OpenBSD, NetBSD and FreeBSD `doas`: `alice ran command id -u as root from /home/alice`,
/// `failed command for mallory: id` and (OpenBSD) `command not permitted for mallory: id`.
fn doas(msg: &str) -> Option<Auth<'_>> {
    if let Some(rest) =
        msg.strip_prefix("failed command for ").or_else(|| msg.strip_prefix("command not permitted for "))
    {
        let (user, command) = rest.split_once(": ")?;
        return Some(Auth { event: "sudo_failure", user, command, ..Auth::default() });
    }
    let (user, rest) = msg.split_once(" ran command ")?;
    let (head, cwd) = rest.rsplit_once(" from ")?;
    let (command, run_as) = head.rsplit_once(" as ")?;
    Some(Auth { event: "sudo_command", user, command, run_as, cwd, ..Auth::default() })
}

/// BSD `login(1)`: `ROOT LOGIN (root) ON ttyv0`, `login on ttyv0 as alice`,
/// `LOGIN FAILURE ON ttyv0, alice`, `3 LOGIN FAILURES ON ttyv0, alice`.
fn bsd_login(msg: &str) -> Option<Auth<'_>> {
    if let Some(rest) = msg.strip_prefix("ROOT LOGIN (") {
        let (user, rest) = rest.split_once(") ")?;
        let tty = rest.strip_prefix("ON ").or_else(|| rest.strip_prefix("on "))?;
        return Some(Auth { event: "login", user, tty: tty.split(' ').next()?, ..Auth::default() });
    }
    if let Some(rest) = msg.strip_prefix("login on ") {
        let (tty, user) = rest.split_once(" as ")?;
        return Some(Auth { event: "login", user: user.split(' ').next()?, tty, ..Auth::default() });
    }
    let (_, rest) = msg.split_once("LOGIN FAILURE")?;
    let rest = rest.strip_prefix("S").unwrap_or(rest).strip_prefix(" ON ")?;
    let (tty, user) = rest.split_once(", ").unwrap_or((rest, ""));
    Some(Auth { event: "auth_failure", user, tty, ..Auth::default() })
}

fn shadow_utils<'a>(program: &str, msg: &'a str) -> Option<Auth<'a>> {
    let (event, name) = match program {
        "useradd" if msg.starts_with("new user: ") => ("account_created", word_after(msg, "name=")?),
        "useradd" | "groupadd" if msg.starts_with("new group: ") => ("group_created", word_after(msg, "name=")?),
        "userdel" if msg.starts_with("delete user '") => ("account_deleted", quoted(msg)?),
        // `add 'USER' to group 'GROUP'`; the `shadow group` line that follows repeats it.
        "usermod" | "gpasswd" if msg.starts_with("add '") && msg.contains("' to group '") => {
            ("group_member_added", quoted(msg)?)
        }
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
    pam_text(rest.split_once("): ")?.1)
}

/// What `pam_unix` says after its own name.
fn pam_text(text: &str) -> Option<Auth<'_>> {
    // `authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=ADDRESS  user=NAME`;
    // `user=` is missing when the account does not exist.
    if let Some(fields) = text.strip_prefix("authentication failure;") {
        let field = |key: &str| fields.split(' ').find_map(|f| f.strip_prefix(key)).unwrap_or_default();
        return Some(Auth {
            event: "auth_failure",
            user: field("user="),
            remote_address: field("rhost="),
            tty: field("tty="),
            ..Auth::default()
        });
    }
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

    /// PAM reports every failed authentication, with the remote host when there is one. Old
    /// releases put `(pam_unix)` in the program name instead of the message.
    #[test]
    fn pam_authentication_failures_are_events() {
        let v = parsed("Mar  9 01:02:03 web01 sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9  user=root\n");
        assert_eq!(
            (v["event"].as_str(), v["user"].as_str(), v["remote_address"].as_str()),
            (Some("auth_failure"), Some("root"), Some("203.0.113.9"))
        );
        let v = parsed("Mar  9 01:02:03 web01 su[7]: pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=0 tty=pts/0 ruser=alice rhost=  user=root\n");
        assert_eq!(
            (v["event"].as_str(), v["user"].as_str(), v["remote_address"].as_str()),
            (Some("auth_failure"), Some("root"), Some(""))
        );
        // No `user=`: the account does not exist.
        let v = parsed("Mar  9 01:02:03 web01 sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9\n");
        assert_eq!((v["event"].as_str(), v["user"].as_str()), (Some("auth_failure"), Some("")));

        let v = parsed("Mar  9 01:02:03 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=203.0.113.9  user=root\n");
        assert_eq!(
            (v["event"].as_str(), v["remote_address"].as_str(), v["pid"].as_u64()),
            (Some("auth_failure"), Some("203.0.113.9"), Some(19939))
        );
        let v = parsed("Mar  9 01:02:03 combo su(pam_unix)[2605]: session opened for user news by (uid=0)\n");
        assert_eq!((v["event"].as_str(), v["user"].as_str()), (Some("session_opened"), Some("news")));
    }

    #[test]
    fn adding_a_user_to_a_group_is_an_event() {
        let v = parsed("Mar  9 01:02:03 web01 usermod[9]: add 'bob' to group 'sudo'\n");
        assert_eq!((v["event"].as_str(), v["user"].as_str()), (Some("group_member_added"), Some("bob")));
        let v = parsed("Mar  9 01:02:03 web01 usermod[9]: add 'bob' to shadow group 'sudo'\n");
        assert_eq!(v["event"].as_str(), Some(""), "the shadow copy of the same change is not a second event");
        let out = run(
            &ARTIFACT,
            "var/log/auth.log",
            b"Mar  9 01:02:03 web01 usermod[9]: add 'bob' to group 'sudo'\n",
            MAR_10_2024,
        );
        assert!(out.contains(",group_member_added,add 'bob' to group 'sudo',"), "{out}");
    }

    /// rsyslog folds identical lines into `message repeated N times: [ ... ]`.
    #[test]
    fn a_repeated_message_is_classified_by_what_it_repeats() {
        let v = parsed("Mar  9 01:02:03 web01 sshd[1]: message repeated 5 times: [ Failed password for root from 203.0.113.9 port 4242 ssh2]\n");
        assert_eq!(
            (v["event"].as_str(), v["user"].as_str(), v["remote_port"].as_u64()),
            (Some("ssh_failed"), Some("root"), Some(4242))
        );
        assert!(v["message"].as_str().unwrap().starts_with("message repeated 5 times"));
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
    fn freebsd_doas_su_and_sudo_lines() {
        let out = run(&ARTIFACT, "var/log/auth.log", &fixture("auth-log/freebsd-auth.log"), 1_794_600_000);
        insta::assert_snapshot!("freebsd", out);
        assert!(out.contains("\"event\":\"sudo_command\",\"user\":\"alice\""));
    }

    #[test]
    fn openbsd_account_and_doas_lines_in_messages_and_secure() {
        let messages = run(&ARTIFACT, "var/log/messages", &fixture("auth-log/openbsd-messages"), 1_794_600_000);
        insta::assert_snapshot!("openbsd_messages", messages);
        // `messages` is a mixed file: only the auth events are records here.
        assert!(
            messages.lines().take_while(|l| l.starts_with('{')).all(|l| !l.contains("\"event\":\"\"")),
            "{messages}"
        );
        let secure = run(&ARTIFACT, "var/log/secure", &fixture("auth-log/openbsd-secure"), 1_794_600_000);
        assert!(
            secure.contains("\"event\":\"sudo_failure\",\"user\":\"mallory\"")
                && secure.contains("\"event\":\"sudo_command\",\"user\":\"alice\""),
            "{secure}"
        );
    }

    #[test]
    fn bsd_message_variants() {
        let line = |program: &str, message: &str| {
            classify(program, message)
                .map(|a| (a.event, a.user.to_string(), a.run_as.to_string(), a.command.to_string(), a.tty.to_string()))
        };
        let event = |program, message| line(program, message).unwrap_or_default();
        assert_eq!(
            event("doas", "alice ran command id -u as root from /home/alice"),
            ("sudo_command", "alice".into(), "root".into(), "id -u".into(), "".into())
        );
        assert_eq!(event("doas", "failed command for mallory: /usr/bin/id").0, "sudo_failure");
        assert_eq!(
            event("su", "BAD SU alice to root on /dev/ttyp0"),
            ("su", "alice".into(), "root".into(), "".into(), "/dev/ttyp0".into())
        );
        assert_eq!(event("su", "alice to root on /dev/pts/0").1, "alice");
        assert_eq!(
            event("login", "ROOT LOGIN (root) ON ttyv0"),
            ("login", "root".into(), "".into(), "".into(), "ttyv0".into())
        );
        assert_eq!(event("login", "login on ttyv0 as bob").1, "bob");
        assert_eq!(
            event("login", "2 LOGIN FAILURES ON ttyv0, alice"),
            ("auth_failure", "alice".into(), "".into(), "".into(), "ttyv0".into())
        );
        assert_eq!(event("login", "LOGIN FAILURE ON ttyv0, mallory").1, "mallory");
        // The Linux forms still go to their own branches.
        assert_eq!(event("su", "(to root) alice on pts/0").3, "");
        assert_eq!(event("su", "FAILED SU (to root) alice on pts/0").0, "su");
        assert!(line("doas", "random text").is_none());
        assert_eq!(event("doas", "command not permitted for mallory: /usr/bin/id -u").0, "sudo_failure");
        let name = |program, message| line(program, message).map(|a| (a.0, a.1)).unwrap_or_default();
        assert_eq!(
            name("useradd", "new user added: name=mallory, uid=1001, gid=1001, home=/home/mallory, shell=/bin/ksh"),
            ("account_created", "mallory".into())
        );
        assert_eq!(
            name("useradd", "New user added: name=alice, uid=1000, gid=100, home=/home/alice, shell=/bin/sh"),
            ("account_created", "alice".into())
        );
        assert_eq!(
            name("usermod", "user information modified: name=bob, uid=1002, gid=1002, home=/home/bob, shell=/bin/ksh")
                .0,
            "account_modified"
        );
        assert_eq!(name("userdel", "user removed: name=carol"), ("account_deleted", "carol".into()));
        assert_eq!(name("userdel", "User removed: name=carol").0, "account_deleted");
        assert_eq!(name("groupadd", "new group added: name=nxgrp, gid=1004"), ("group_created", "nxgrp".into()));
        assert_eq!(name("groupdel", "group deleted: name=nxgrp"), ("group_deleted", "nxgrp".into()));
        // The Linux shadow-utils forms keep their branch.
        assert_eq!(
            name("useradd", "new user: name=alice, UID=1000, GID=1000, home=/home/alice, shell=/bin/bash, from=none").0,
            "account_created"
        );
        assert!(line("useradd", "something else entirely").is_none());
        let timeline = run(
            &ARTIFACT,
            "var/log/authlog",
            b"Nov 13 01:08:52 h doas[1308]: failed command for mallory: /usr/bin/id\n",
            1_794_600_000,
        );
        assert!(timeline.contains("sudo refused mallory"), "{timeline}");
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

    /// illumos syslog puts `[ID 800047 auth.info] ` in front of every message, and `su` and `login` write their own
    /// phrases: the lines of a real `authlog` classify as the OpenSSH and PAM ones do.
    #[test]
    fn solaris_message_ids_su_and_login_lines() {
        const NOV_13_2026: i64 = 1_794_535_000;
        let data = fixture("auth-log/solaris_authlog");
        let out = run(&ARTIFACT, "var/log/authlog", &data, NOV_13_2026);
        insta::assert_snapshot!("solaris", out);
        let text = String::from_utf8(data).unwrap();
        let count = |event: &str| out.matches(&format!(r#""event":"{event}""#)).count();
        let lines = |needle: &str| text.lines().filter(|l| l.contains(needle)).count();
        assert_eq!(count("ssh_accepted"), lines("Accepted publickey"));
        assert_eq!(count("ssh_failed"), lines("Failed password"));
        assert_eq!(count("ssh_invalid_user"), lines("Invalid user"));
        assert_eq!(count("su"), lines("su: [ID"));
        assert_eq!(count("auth_failure"), lines("REPEATED LOGIN FAILURES"));
        assert!(count("ssh_accepted") >= 5 && count("su") >= 2, "{out}");
        assert!(out.contains(r#""event":"su","user":"alice","remote_address":"""#) || out.contains(r#""user":"alice","remote_address":"","remote_port":null,"method":"","key_fingerprint":"","command":"","run_as":"root","cwd":"","tty":"pts/1""#), "{out}");
        let timeline = out.split("--- timeline ---\n").nth(1).unwrap();
        assert!(timeline.contains("failed su to root by alice") && timeline.contains("alice su to root"), "{timeline}");
    }

    #[test]
    fn solaris_su_login_forms_one_by_one() {
        let one = |line: &str| {
            let out = run(&ARTIFACT, "var/log/authlog", line.as_bytes(), MAR_10_2024);
            serde_json::from_str::<serde_json::Value>(out.lines().next().unwrap()).unwrap()
        };
        let ok = one("Mar  9 01:02:03 h su: [ID 366847 auth.notice] 'su root' succeeded for alice on /dev/pts/1");
        assert_eq!(
            (ok["event"].as_str(), ok["user"].as_str(), ok["run_as"].as_str(), ok["tty"].as_str()),
            (Some("su"), Some("alice"), Some("root"), Some("pts/1"))
        );
        let bad = one("Mar  9 01:02:03 h su: [ID 810491 auth.crit] 'su - bob' failed for alice on /dev/pts/2");
        assert_eq!((bad["user"].as_str(), bad["run_as"].as_str()), (Some("alice"), Some("bob")));
        let plain = one("Mar  9 01:02:03 h su: [ID 366847 auth.info] 'su' succeeded for root on /dev/???");
        assert_eq!(plain["run_as"].as_str(), Some("root"));
        let repeated =
            one("Mar  9 01:02:03 h login: [ID 561941 auth.crit] REPEATED LOGIN FAILURES ON /dev/pts/1, mallory");
        assert_eq!(
            (repeated["event"].as_str(), repeated["user"].as_str(), repeated["tty"].as_str()),
            (Some("auth_failure"), Some("mallory"), Some("pts/1"))
        );
        let root = one("Mar  9 01:02:03 h login: [ID 644210 auth.notice] ROOT LOGIN /dev/console");
        assert_eq!(
            (root["event"].as_str(), root["user"].as_str(), root["tty"].as_str()),
            (Some("session_opened"), Some("root"), Some("console"))
        );
        // A bracket that is not a message id stays part of the message; a bare `[ID` is not cut.
        assert_eq!(
            one("Mar  9 01:02:03 h sshd[1]: [ID x] Accepted publickey for a from 1.2.3.4 port 1 ssh2")["event"]
                .as_str(),
            Some("")
        );
        assert_eq!(without_message_id("[ID 1 auth.info"), "[ID 1 auth.info");
    }

    /// `var/adm/messages` mixes everything: only the authentication lines are kept.
    #[test]
    fn var_adm_messages_keeps_only_authentication_events() {
        let data = b"Nov 13 01:16:21 h su: [ID 366847 auth.notice] 'su root' succeeded for alice on /dev/pts/1\nNov 13 01:16:51 h svc.startd[9]: [ID 748625 daemon.error] site/x:default failed: transitioned to maintenance\n";
        let out = run(&ARTIFACT, "var/adm/messages", data, 1_794_535_000);
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 1, "{out}");
        assert!(out.contains(r#""event":"su""#), "{out}");
    }
}
