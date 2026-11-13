//! FTP server logs: vsftpd's own `vsftpd.log` and the wu-ftpd `xferlog` that vsftpd, ProFTPD
//! (`TransferLog`) and wu-ftpd write. Formats: vsftpd.conf(5) (`xferlog_std_format`,
//! `vsftpd_log_file`) and the xferlog format of the wu-ftpd `xferlog(5)` manual page.
//!
//! The times are the host's local time with no zone and are marked as an assumed zone. The
//! anonymous password vsftpd logs (`anon password "a@b"`) is an e-mail address by convention and
//! is kept; no other password is ever logged by these servers.

use crate::common::logfmt::ctime_wall;
use crate::common::logfmt::Unparsed;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, UNIX};
use nixcavate_core::{Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const VSFTPD: Artifact = Artifact::new(
    "vsftpd-log",
    "vsftpd.log: FTP connections, logins and file operations",
    Category::Logs,
    UNIX,
    &["var/log/vsftpd.log*", "var/log/vsftpd/vsftpd.log*"],
    parse_vsftpd,
)
.split_lines();

pub const XFERLOG: Artifact = Artifact::new(
    "xferlog",
    "FTP transfer log (wu-ftpd xferlog: vsftpd, ProFTPD, wu-ftpd)",
    Category::Logs,
    UNIX,
    &["var/log/xferlog*", "var/log/vsftpd/xferlog*", "var/log/proftpd/xferlog*", "var/log/proftpd/transfer.log*"],
    parse_xferlog,
)
.split_lines();

#[derive(Serialize)]
struct Vsftpd<'a> {
    time: Option<Timestamp>,
    pid: Option<u32>,
    user: Option<&'a str>,
    /// `OK` or `FAIL`; empty for `CONNECT`.
    result: &'a str,
    /// `CONNECT`, `LOGIN`, `UPLOAD`, `DOWNLOAD`, `DELETE`, `MKDIR`, `RMDIR`, `RENAME`...
    action: &'a str,
    client: Option<&'a str>,
    path: Option<&'a str>,
    bytes: Option<u64>,
    /// What follows the client: the anonymous password, a rate, a rename target.
    detail: &'a str,
}

impl Record for Vsftpd<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let kind = match (self.action, self.result) {
            ("LOGIN", "OK") => "ftp_login",
            ("LOGIN", _) => "ftp_login_failed",
            ("UPLOAD" | "DOWNLOAD", _) => "ftp_transfer",
            ("DELETE" | "MKDIR" | "RMDIR" | "RENAME", _) => "ftp_file_change",
            _ => return None.into_iter(),
        };
        let message = format!(
            "{} {} {} {} {}",
            self.user.unwrap_or("-"),
            self.client.unwrap_or("-"),
            self.result,
            self.action,
            self.path.unwrap_or_default()
        );
        self.time.map(|t| Event::new(t, kind, message)).into_iter()
    }
}

fn parse_vsftpd(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut unparsed = Unparsed::default();
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if text.is_empty() {
            return Ok(());
        }
        match vsftpd_line(input, text) {
            Some(record) => sink.emit(Loc::Offset(line.offset), &record),
            None => {
                unparsed.note(line.number);
                Ok(())
            }
        }
    })?;
    unparsed.report(sink, "vsftpd.log");
    Ok(())
}

/// `Fri Nov 13 01:22:03 2026 [pid 3838] [alice] OK DOWNLOAD: Client "127.0.0.1", "/f", 20000 bytes, 7Kbyte/sec`
fn vsftpd_line<'a>(input: &Input, text: &'a str) -> Option<Vsftpd<'a>> {
    let wall = ctime_wall(text.as_bytes())?;
    let rest = text.get(24..)?.strip_prefix(" [pid ")?;
    let (pid, rest) = rest.split_once("] ")?;
    let (user, rest) = match rest.strip_prefix('[') {
        Some(after) => {
            let (user, rest) = after.split_once("] ")?;
            (Some(user), rest)
        }
        None => (None, rest),
    };
    let (head, tail) = rest.split_once(": ")?;
    let (result, action) = head.split_once(' ').unwrap_or(("", head));
    let (result, action) = if matches!(result, "OK" | "FAIL") { (result, action) } else { ("", head) };
    let tail = tail.strip_prefix("Client \"")?;
    let (client, tail) = tail.split_once('"')?;
    let tail = tail.strip_prefix(", ").unwrap_or(tail);
    let (path, tail) = match tail.strip_prefix('"') {
        Some(after) => {
            // The path ends at the quote followed by a comma or the end of the line.
            let end = after.find("\", ").or_else(|| after.strip_suffix('"').map(str::len))?;
            (Some(after.get(..end)?), after.get(end + 1..)?.trim_start_matches(", "))
        }
        None => (None, tail),
    };
    let bytes = tail.split_once(" bytes").and_then(|(n, _)| n.parse().ok());
    Some(Vsftpd {
        time: Some(input.local_time(wall, 0, Precision::Seconds)),
        pid: pid.parse().ok(),
        user,
        result,
        action,
        client: Some(client),
        path,
        bytes,
        detail: tail,
    })
}

#[derive(Serialize)]
struct Xfer<'a> {
    time: Option<Timestamp>,
    duration_secs: Option<u64>,
    client: &'a str,
    bytes: Option<u64>,
    path: &'a str,
    /// `ascii` or `binary`.
    transfer_type: &'a str,
    /// `compressed`, `uncompressed`, `tar`, or empty (`_`).
    special_action: &'a str,
    /// `download` (outgoing), `upload` (incoming) or `delete`.
    direction: &'a str,
    /// `anonymous`, `guest` or `real`.
    access_mode: &'a str,
    user: &'a str,
    service: &'a str,
    complete: Option<bool>,
}

impl Record for Xfer<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("{} {} {} {} bytes", self.user, self.direction, self.path, self.bytes.unwrap_or(0));
        let kind = if self.direction == "delete" { "ftp_file_change" } else { "ftp_transfer" };
        self.time.map(|t| Event::new(t, kind, message)).into_iter()
    }
}

fn parse_xferlog(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut unparsed = Unparsed::default();
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if text.is_empty() {
            return Ok(());
        }
        match xfer_line(input, text) {
            Some(record) => sink.emit(Loc::Offset(line.offset), &record),
            // FreeBSD's newsyslog marks the file's creation and each turn-over in syslog form.
            None if text.contains(" newsyslog[") && text.contains("]: logfile ") => Ok(()),
            None => {
                unparsed.note(line.number);
                Ok(())
            }
        }
    })?;
    unparsed.report(sink, "xferlog");
    Ok(())
}

/// `Fri Nov 13 01:22:03 2026 1 127.0.0.1 20000 /home/a/f b _ o r alice ftp 0 * c`. The file name
/// may contain spaces, so the nine fixed fields are taken from the right.
fn xfer_line<'a>(input: &Input, text: &'a str) -> Option<Xfer<'a>> {
    let wall = ctime_wall(text.as_bytes())?;
    let rest = text.get(24..)?.trim_start();
    let (duration, rest) = rest.split_once(' ')?;
    let (client, rest) = rest.split_once(' ')?;
    let (size, rest) = rest.split_once(' ')?;
    let mut tail = rest.rsplitn(10, ' ');
    let complete = tail.next()?;
    let (_id, _method, service, user, mode, direction, special, kind) = (
        tail.next()?,
        tail.next()?,
        tail.next()?,
        tail.next()?,
        tail.next()?,
        tail.next()?,
        tail.next()?,
        tail.next()?,
    );
    let path = tail.next()?;
    Some(Xfer {
        time: Some(input.local_time(wall, 0, Precision::Seconds)),
        duration_secs: duration.parse().ok(),
        client,
        bytes: size.parse().ok(),
        path,
        transfer_type: match kind {
            "a" => "ascii",
            "b" => "binary",
            other => other,
        },
        special_action: match special {
            "C" => "compressed",
            "U" => "uncompressed",
            "T" => "tar",
            _ => "",
        },
        direction: match direction {
            "o" => "download",
            "i" => "upload",
            "d" => "delete",
            other => other,
        },
        access_mode: match mode {
            "a" => "anonymous",
            "g" => "guest",
            "r" => "real",
            other => other,
        },
        user,
        service,
        complete: match complete {
            "c" => Some(true),
            "i" => Some(false),
            _ => None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    fn records(out: &str) -> Vec<&str> {
        out.lines().take_while(|l| !l.starts_with("---")).collect()
    }

    /// Fixture: real vsftpd 3.0.3 driven by ftplib: 1 login, 1 download, 2 uploads, delete, mkdir, rmdir,
    /// 2 failed logins, 1 anonymous login, 4 connections (xferlog and vsftpd.log from `dual_log_enable`).
    #[test]
    fn vsftpd_log_matches_the_session() {
        let data = fixture("svclogs/vsftpd/vsftpd.log");
        let out = run(&VSFTPD, "var/log/vsftpd.log", &data, 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        assert_eq!(records(&out).len(), data.split(|b| *b == b'\n').filter(|l| !l.is_empty()).count());
        assert_eq!(out.matches("\"action\":\"CONNECT\"").count(), 4);
        assert_eq!(out.matches("\"result\":\"FAIL\",\"action\":\"LOGIN\"").count(), 2);
        assert!(out.contains("\"path\":\"/home/alice/new file.txt\",\"bytes\":500"), "{out}");
        assert!(out.contains("\"time\":\"2026-11-13T01:22:03Z\""), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn xferlog_fields_and_directions() {
        let data = fixture("svclogs/vsftpd/xferlog");
        let out = run(&XFERLOG, "var/log/xferlog", &data, 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        assert_eq!(records(&out).len(), 3);
        assert!(
            out.contains("\"bytes\":20000,\"path\":\"/home/alice/big.bin\",\"transfer_type\":\"binary\"")
                && out.contains("\"direction\":\"download\""),
            "{out}"
        );
        assert!(out.contains("\"direction\":\"upload\",\"access_mode\":\"real\",\"user\":\"alice\""), "{out}");
        // A file name with spaces, as wu-ftpd writes it.
        let spaced = b"Fri Nov 13 01:22:03 2026 1 10.0.0.9 5 /srv/a b c.txt a _ i a anon@x ftp 0 * c\n";
        assert!(run(&XFERLOG, "var/log/xferlog", spaced, 0).contains("\"path\":\"/srv/a b c.txt\""));
    }

    /// FreeBSD's newsyslog starts every log it creates or turns over with a line of its own.
    #[test]
    fn the_newsyslog_line_is_not_a_transfer() {
        let log = b"Nov 13 01:35:08 host newsyslog[779]: logfile first created\n";
        let out = run(&XFERLOG, "var/log/xferlog", log, 0);
        assert!(!out.contains("warning") && !out.contains("failed"), "{out}");
    }

    #[test]
    fn hostile_lines_never_panic() {
        let mut seed = 77u64;
        for (artifact, name) in [(&VSFTPD, "svclogs/vsftpd/vsftpd.log"), (&XFERLOG, "svclogs/vsftpd/xferlog")] {
            let full = fixture(name);
            for cut in 0..full.len() {
                run(artifact, "var/log/x", &full[..cut], 0);
            }
            for _ in 0..800 {
                let mut copy = full.clone();
                for _ in 0..3 {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let at = (seed >> 33) as usize % copy.len();
                    copy[at] = (seed >> 20) as u8;
                }
                run(artifact, "var/log/x", &copy, 0);
            }
        }
    }
}
