//! Samba logs: the daemon logs (`log.smbd`, `log.nmbd`, `log.<client>`) and the `full_audit` VFS
//! module's lines. Formats: smb.conf(5) `log file`/`debug` options (the two-line entry
//! `[2024/03/10 01:02:03.123456,  1] ../../source3/smbd/server.c:1741(main)` followed by the
//! indented message) and vfs_full_audit(8) (`prefix` fields separated by `|`, then the operation,
//! the result `ok`/`fail` and the arguments).
//!
//! The daemon log time has no zone and is marked as an assumed zone. The audit lines are read
//! from the files rsyslog or syslog-ng write them to (`var/log/samba/audit*`): the syslog prefix
//! is decoded with the common syslog header. The `prefix` is site configuration; the operation
//! is found as the first field that names a `full_audit` operation, the fields before it are the
//! user, the client address and (when logged) the share.

use crate::common::logfmt::{cut, Unparsed};
use crate::common::syslog::parse_header;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, UNIX};
use nixcavate_core::time::{parse_uint, secs_from_civil};
use nixcavate_core::{Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const SAMBA: Artifact = Artifact::new(
    "samba-log",
    "Samba daemon logs: authentication and service connections",
    Category::Logs,
    UNIX,
    &["var/log/samba/log.*", "var/log/samba/smbd.log*", "var/log/samba/nmbd.log*", "var/log/samba/samba.log*"],
    parse_samba,
);

pub const SAMBA_AUDIT: Artifact = Artifact::new(
    "samba-audit",
    "Samba full_audit log: file operations per user, client and share",
    Category::Logs,
    UNIX,
    &["var/log/samba/audit*", "var/log/samba/*audit*", "var/log/samba_audit*", "var/log/smbd_audit*"],
    parse_audit,
)
.split_lines();

#[derive(Serialize)]
struct Entry {
    time: Option<Timestamp>,
    level: Option<u32>,
    /// `../../source3/auth/auth.c:268(auth_check_ntlm_password)`.
    source: String,
    /// `samba_login`, `samba_login_failed`, or empty.
    event: Option<&'static str>,
    user: Option<String>,
    /// The NT status of a failed authentication.
    status: Option<String>,
    message: String,
}

impl Record for Entry {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message =
            format!("{} {}", self.user.as_deref().unwrap_or("-"), self.status.as_deref().unwrap_or("authenticated"));
        self.time.zip(self.event).map(|(t, kind)| Event::new(t, kind, message)).into_iter()
    }
}

/// `[2026/11/13 01:22:34.412191,  3] ../../auth/gensec/gensec_start.c:1083(gensec_register)`
fn header(input: &Input, text: &str) -> Option<(Option<Timestamp>, Option<u32>, String)> {
    let inner = text.strip_prefix('[')?;
    let (stamp, rest) = inner.split_once(',')?;
    let (level, source) = rest.split_once("] ")?;
    let b = stamp.as_bytes();
    let num = |from: usize, len: usize| parse_uint(b.get(from..from + len)?).and_then(|v| u32::try_from(v).ok());
    if b.get(4) != Some(&b'/')
        || b.get(7) != Some(&b'/')
        || b.get(10) != Some(&b' ')
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
    {
        return None;
    }
    let wall = secs_from_civil(i64::from(num(0, 4)?), num(5, 2)?, num(8, 2)?, num(11, 2)?, num(14, 2)?, num(17, 2)?);
    let (nanos, precision) = match b.get(19) {
        Some(b'.') => {
            let digits = b.get(20..)?.len().min(9);
            let frac = u32::try_from(parse_uint(b.get(20..20 + digits)?)?).ok()?;
            (frac.checked_mul(10u32.pow(9 - digits as u32))?, Precision::Micros)
        }
        _ => (0, Precision::Seconds),
    };
    let time = wall.map(|w| input.local_time(w, nanos, precision));
    Some((time, level.trim().parse().ok(), source.trim().to_string()))
}

fn classify(message: &str) -> (Option<&'static str>, Option<String>, Option<String>) {
    // `check_ntlm_password:  authentication for user [alice] -> [alice] -> [alice] succeeded`
    // `check_ntlm_password:  Authentication for user [bob] -> [bob] FAILED with error NT_STATUS_WRONG_PASSWORD, authoritative=1`
    let Some(rest) = message.strip_prefix("check_ntlm_password:").map(str::trim_start) else {
        return (None, None, None);
    };
    let Some(rest) =
        rest.strip_prefix("authentication for user [").or_else(|| rest.strip_prefix("Authentication for user ["))
    else {
        return (None, None, None);
    };
    let user = rest.split(']').next().unwrap_or_default().to_string();
    if rest.ends_with(" succeeded") && !user.is_empty() {
        return (Some("samba_login"), Some(user), None);
    }
    if let Some((_, status)) = rest.split_once("FAILED with error ") {
        let status = status.split([',', ' ']).next().unwrap_or_default().to_string();
        return (Some("samba_login_failed"), Some(user), Some(status));
    }
    (None, None, None)
}

fn parse_samba(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut pending: Option<(u64, Entry)> = None;
    let mut seen = false;
    let mut stray = Unparsed::default();
    let flush = |pending: &mut Option<(u64, Entry)>, sink: &mut Sink| -> Result<()> {
        if let Some((line, mut entry)) = pending.take() {
            let (event, user, status) = classify(&entry.message);
            (entry.event, entry.user, entry.status) = (event, user, status);
            sink.emit(Loc::Line(line), &entry)?;
        }
        Ok(())
    };
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if text.is_empty() {
            return Ok(());
        }
        if let Some((time, level, source)) = header(input, text) {
            flush(&mut pending, sink)?;
            seen = true;
            pending = Some((
                line.number,
                Entry { time, level, source, event: None, user: None, status: None, message: String::new() },
            ));
        } else if let Some((_, entry)) = pending.as_mut() {
            if entry.message.len() < (1 << 20) {
                if !entry.message.is_empty() {
                    entry.message.push('\n');
                }
                entry.message.push_str(text.trim_start());
            }
        } else if !seen {
            return Err(Error::format("not a Samba log: the first line is not a `[date, level] source` header"));
        } else {
            stray.note(line.number);
        }
        Ok(())
    })?;
    flush(&mut pending, sink)?;
    stray.report(sink, "Samba log");
    if seen {
        Ok(())
    } else {
        Err(Error::skipped("empty file"))
    }
}

// ---- full_audit ----

const OPERATIONS: &[&str] = &[
    "connect",
    "disconnect",
    "open",
    "openat",
    "close",
    "read",
    "pread",
    "write",
    "pwrite",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "mkdir",
    "mkdirat",
    "rmdir",
    "opendir",
    "readdir",
    "chmod",
    "fchmod",
    "chown",
    "fchown",
    "lchown",
    "link",
    "symlink",
    "symlinkat",
    "readlink",
    "readlinkat",
    "sendfile",
    "ftruncate",
    "ntimes",
    "mknod",
    "mknodat",
    "chdir",
    "rewinddir",
    "fsetxattr",
    "setxattr",
    "getxattr",
    "removexattr",
    "set_nt_acl",
    "fset_nt_acl",
    "linkat",
    "stat",
    "lstat",
    "fstat",
    "fstatat",
    "lock",
    "create_file",
    "closedir",
    "seekdir",
    "telldir",
];

#[derive(Serialize)]
struct Audit<'a> {
    time: Option<Timestamp>,
    log_host: &'a str,
    user: &'a str,
    client_ip: &'a str,
    share: Option<&'a str>,
    operation: &'a str,
    /// `ok` or `fail`.
    result: &'a str,
    /// The remaining fields: the open mode, the path, the second path of a rename.
    arguments: &'a str,
}

impl Record for Audit<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "{}@{} {} {} {} {}",
            self.user,
            self.client_ip,
            self.share.unwrap_or("-"),
            self.operation,
            self.result,
            cut(self.arguments)
        );
        self.time.map(|t| Event::new(t, "smb_file_op", message)).into_iter()
    }
}

fn parse_audit(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut unparsed = Unparsed::default();
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let header = parse_header(input, text.trim_end().as_bytes());
        // Only the lines of the audit module; other programs sharing the file are not records.
        // The syslog header already took `smbd_audit:` as the program name.
        let body = match header.program.as_ref() {
            "smbd_audit" => &*header.message,
            _ => match header.message.strip_prefix("smbd_audit: ") {
                Some(body) => body,
                None => return Ok(()),
            },
        };
        let fields: Vec<&str> = body.split('|').collect();
        let Some(at) = fields.iter().position(|f| OPERATIONS.contains(f)).filter(|&i| i >= 2) else {
            unparsed.note(line.number);
            return Ok(());
        };
        let result = fields.get(at + 1).copied().unwrap_or_default();
        // The argument text is the tail of the line, kept as logged (it may contain `|`).
        let arguments = fields.get(at + 2..).map(|a| a.join("|")).unwrap_or_default();
        sink.emit(
            Loc::Offset(line.offset),
            &Audit {
                time: header.time,
                log_host: &header.log_host,
                user: fields[0],
                client_ip: fields[1],
                share: fields.get(2).copied().filter(|_| at > 2),
                operation: fields[at],
                result,
                arguments: &arguments,
            },
        )
    })?;
    unparsed.report(sink, "full_audit");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    fn records(out: &str) -> Vec<&str> {
        out.lines().take_while(|l| !l.starts_with("---")).collect()
    }

    /// Fixture: real Samba 4.17.12 (`log level = 1 auth:3`) driven by smbclient: 1 good login
    /// (plus an anonymous one for `-L`), a wrong password, an unknown user and a second unknown user.
    #[test]
    fn samba_log_entries_and_logins() {
        let data = fixture("svclogs/samba/log.client");
        let out = run(&SAMBA, "var/log/samba/log.client", &data, 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        let headers = String::from_utf8_lossy(&data).lines().filter(|l| l.starts_with("[20")).count();
        assert_eq!(records(&out).len(), headers);
        assert_eq!(out.matches("\"event\":\"samba_login\"").count(), 1);
        assert_eq!(out.matches("\"event\":\"samba_login_failed\"").count(), 3);
        assert!(out.contains("\"user\":\"alice\",\"status\":\"NT_STATUS_WRONG_PASSWORD\""), "{out}");
        assert!(out.contains("\"user\":\"nosuch\",\"status\":\"NT_STATUS_NO_SUCH_USER\""), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn smbd_startup_log() {
        let out = run(&SAMBA, "var/log/samba/log.smbd", &fixture("svclogs/samba/log.smbd"), 0);
        assert!(out.contains("smbd version 4.17.12-Debian started.\\nCopyright Andrew Tridgell"), "{out}");
        assert!(run(&SAMBA, "var/log/samba/log.smbd", b"hello\n", 0).contains("not a Samba log"));
    }

    /// The `full_audit` lines of the same session: 35 operations, 1 rename, 1 mkdir, 2 unlinks.
    #[test]
    fn full_audit_lines() {
        let data = fixture("svclogs/samba/audit.log");
        let out = run(&SAMBA_AUDIT, "var/log/samba/audit.log", &data, 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        assert_eq!(records(&out).len(), 35);
        assert_eq!(out.matches("\"operation\":\"unlinkat\"").count(), 2);
        assert!(
            out.contains(
                "\"operation\":\"renameat\",\"result\":\"ok\",\"arguments\":\"/srv/share/up.txt|/srv/share/moved.txt\""
            ),
            "{out}"
        );
        assert!(out.contains("\"user\":\"alice\",\"client_ip\":\"127.0.0.1\",\"share\":\"share\""), "{out}");
        // A site whose prefix is only `%u|%I`.
        let short = b"2024-03-10T01:02:03+00:00 h smbd_audit: bob|192.0.2.7|unlinkat|ok|/x\n";
        assert!(run(&SAMBA_AUDIT, "var/log/samba/audit.log", short, 0).contains("\"share\":null"));
    }

    #[test]
    fn hostile_input_never_panics() {
        let mut seed = 5u64;
        for (artifact, name) in [(&SAMBA, "svclogs/samba/log.client"), (&SAMBA_AUDIT, "svclogs/samba/audit.log")] {
            let full = fixture(name);
            for cut in (0..full.len()).step_by(7) {
                run(artifact, "var/log/samba/x", &full[..cut], 0);
            }
            for _ in 0..600 {
                let mut copy = full[..3000.min(full.len())].to_vec();
                for _ in 0..4 {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let at = (seed >> 33) as usize % copy.len();
                    copy[at] = (seed >> 20) as u8;
                }
                run(artifact, "var/log/samba/x", &copy, 0);
            }
        }
    }
}
