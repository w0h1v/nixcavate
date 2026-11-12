//! `/var/log/audit/audit.log`: Linux Audit records. Format: auditd(8), the audit-userspace
//! field dictionary and the Red Hat Security Guide chapter "Understanding Audit log files".
//!
//! One line is one record (`type=X msg=audit(secs.millis:serial): key=value ...`), optionally
//! prefixed by `node=`, optionally followed by an enriched section (an uppercase `KEY=value`
//! list after a 0x1D byte). Records of one event share a serial; joining them is left to the
//! analyst, so every line parses on its own.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use memchr::{memchr, memrchr};
use nixcavate_core::time::parse_uint;
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;
use std::fmt::Write;

pub const ARTIFACT: Artifact =
    Artifact::new("audit-log", "Linux audit records", Category::Logs, LINUX, &["var/log/audit/audit.log*"], parse)
        .split_lines();

#[derive(Serialize, Default)]
struct Audit<'a> {
    time: Option<Timestamp>,
    serial: u64,
    record_type: &'a str,
    node: Option<&'a str>,
    pid: Option<u32>,
    ppid: Option<u32>,
    uid: Option<u32>,
    auid: Option<u32>,
    euid: Option<u32>,
    ses: Option<u32>,
    user: Option<Cow<'a, str>>,
    comm: Option<Cow<'a, str>>,
    exe: Option<Cow<'a, str>>,
    syscall: Option<&'a str>,
    success: Option<bool>,
    key: Option<Cow<'a, str>>,
    command: Option<Cow<'a, str>>,
    cwd: Option<Cow<'a, str>>,
    path: Option<Cow<'a, str>>,
    remote_address: Option<&'a str>,
    remote_host: Option<&'a str>,
    terminal: Option<&'a str>,
    op: Option<&'a str>,
    /// Everything after the `msg=audit(...): ` stamp, undecoded.
    fields: &'a str,
    /// Only used for the timeline message of `SERVICE_*` records.
    #[serde(skip)]
    unit: Option<&'a str>,
}

impl Record for Audit<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let Some(time) = self.time else { return None.into_iter() };
        let t = self.record_type;
        let (kind, message) = match t {
            "EXECVE" => ("executed", self.command.as_deref().unwrap_or_default().to_string()),
            "USER_LOGIN" | "USER_AUTH" | "USER_ACCT" | "USER_START" | "USER_END" | "USER_ERR" | "USER_CMD"
            | "CRED_ACQ" | "CRED_DISP" => ("auth", self.summary(false)),
            "ADD_USER" | "DEL_USER" | "ADD_GROUP" | "DEL_GROUP" | "USER_CHAUTHTOK" | "USER_MGMT" | "GRP_MGMT" => {
                ("account_change", self.summary(false))
            }
            "SERVICE_START" | "SERVICE_STOP" => {
                let mut m = format!("{t} {}", self.unit.unwrap_or_default());
                self.push_result(&mut m);
                ("service", m)
            }
            "AVC" => ("anomaly", self.summary(true)),
            _ if t.starts_with("ANOM_") => ("anomaly", self.summary(true)),
            "SYSCALL" => match self.key.as_deref() {
                Some(k) if k != "(null)" => ("audit_rule", format!("{k} {}", self.exe.as_deref().unwrap_or_default())),
                _ => return None.into_iter(),
            },
            _ => return None.into_iter(),
        };
        Some(Event::new(time, kind, message)).into_iter()
    }
}

impl Audit<'_> {
    fn push_result(&self, m: &mut String) {
        if let Some(ok) = self.success {
            m.push_str(if ok { " res=success" } else { " res=failed" });
        }
    }

    /// `TYPE op=.. acct=.. addr=.. res=..`, leaving out what the record does not carry.
    fn summary(&self, with_program: bool) -> String {
        let mut m = String::from(self.record_type);
        let mut add = |name: &str, value: Option<&str>| {
            if let Some(v) = value.filter(|v| *v != "?") {
                let _ = write!(m, " {name}={v}");
            }
        };
        add("op", self.op);
        add("acct", self.user.as_deref());
        add("addr", self.remote_address.or(self.remote_host));
        add("cmd", self.command.as_deref());
        if with_program {
            add("prog", self.exe.as_deref().or(self.comm.as_deref()));
        }
        self.push_result(&mut m);
        m
    }
}

/// Decodes the hex form the kernel uses for untrusted strings: even length, all hex digits.
fn unhex(value: &str, nul_as_space: bool) -> Option<String> {
    let b = value.as_bytes();
    if b.is_empty() || b.len() % 2 != 0 || !b.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let nibble = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
    let bytes: Vec<u8> = b
        .chunks_exact(2)
        .map(|p| {
            let v = nibble(p[0]) << 4 | nibble(p[1]);
            if nul_as_space && v == 0 {
                b' '
            } else {
                v
            }
        })
        .collect();
    Some(String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

/// A string field: bare values are hex when the field is one the kernel may encode.
fn text<'a>(value: &'a str, quoted: bool, encodable: bool) -> Cow<'a, str> {
    if encodable && !quoted {
        if let Some(s) = unhex(value, false) {
            return Cow::Owned(s);
        }
    }
    Cow::Borrowed(value)
}

fn put<'a>(slot: &mut Option<Cow<'a, str>>, value: &'a str, quoted: bool, encodable: bool) {
    if slot.is_none() {
        *slot = Some(text(value, quoted, encodable));
    }
}

fn num(value: &str) -> Option<u32> {
    parse_uint(value.as_bytes()).and_then(|n| u32::try_from(n).ok())
}

/// Calls `f(key, value, quoted)` for each `key=value` in `s`. Tokens without `=` (AVC's
/// `denied { read }`) are skipped; a top-level `msg='...'` is entered rather than returned
/// (`nested` is set inside it, where `msg=` is a plain value, so recursion is one level deep).
fn scan<'a>(mut s: &'a str, nested: bool, f: &mut impl FnMut(&'a str, &'a str, bool)) {
    loop {
        s = s.trim_start_matches(' ');
        let b = s.as_bytes();
        if b.is_empty() {
            return;
        }
        let space = memchr(b' ', b).unwrap_or(b.len());
        let eq = match memchr(b'=', &b[..space]) {
            Some(eq) if eq > 0 => eq,
            _ => {
                s = &s[space..];
                continue;
            }
        };
        let (key, rest) = (&s[..eq], &s[eq + 1..]);
        match rest.as_bytes().first() {
            Some(b'"') => {
                let inner = &rest[1..];
                match memchr(b'"', inner.as_bytes()) {
                    Some(end) => {
                        f(key, &inner[..end], true);
                        s = &inner[end + 1..];
                    }
                    None => return f(key, inner, true),
                }
            }
            Some(b'\'') if key == "msg" && !nested => {
                let inner = &rest[1..];
                match memrchr(b'\'', inner.as_bytes()) {
                    Some(end) => {
                        scan(&inner[..end], true, f);
                        s = &inner[end + 1..];
                    }
                    None => return scan(inner, true, f),
                }
            }
            _ => {
                let end = memchr(b' ', rest.as_bytes()).unwrap_or(rest.len());
                f(key, &rest[..end], false);
                s = &rest[end..];
            }
        }
    }
}

/// The state needed while reading one line, beyond what lands in the record.
#[derive(Default)]
struct Scratch<'a> {
    auid_name: Option<&'a str>,
    uid_name: Option<&'a str>,
    res: Option<bool>,
    argc: Option<u32>,
    args: u32,
    last_arg: Option<u32>,
    command: Option<String>,
}

/// Splits the line header off: `[node=H ]type=T msg=audit(S.MMM:N): `. Returns the record
/// with its stamp filled in and the text after the stamp.
fn header(text: &str) -> Option<(Audit<'_>, &str)> {
    let mut rest = text;
    let mut node = None;
    if let Some(r) = rest.strip_prefix("node=") {
        let end = memchr(b' ', r.as_bytes())?;
        node = Some(&r[..end]);
        rest = r[end..].trim_start_matches(' ');
    }
    let rest = rest.strip_prefix("type=")?;
    let end = memchr(b' ', rest.as_bytes())?;
    let record_type = &rest[..end];
    let rest = rest[end..].trim_start_matches(' ').strip_prefix("msg=audit(")?;
    let close = memchr(b')', rest.as_bytes())?;
    let (stamp, serial) = rest[..close].split_once(':')?;
    let (secs, frac) = stamp.split_once('.').unwrap_or((stamp, ""));
    // Digits only (so ASCII), so the cut below is on a character boundary.
    if !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let frac = &frac[..frac.len().min(3)];
    let millis = parse_uint(frac.as_bytes()).unwrap_or(0) * 10u64.pow(3 - frac.len() as u32);
    let secs = i64::try_from(parse_uint(secs.as_bytes())?).ok()?;
    let after = rest[close + 1..].strip_prefix(':')?.trim_start_matches(' ');
    let audit = Audit {
        time: Some(Timestamp::from_millis(secs.saturating_mul(1000).saturating_add(millis as i64), Basis::Recorded)),
        serial: parse_uint(serial.as_bytes())?,
        record_type,
        node,
        fields: after,
        ..Audit::default()
    };
    Some((audit, after))
}

fn parse_line<'a>(line: &'a str, warn: &mut dyn FnMut(String)) -> Option<Audit<'a>> {
    let (mut r, after) = header(line)?;
    let (body, enriched) = match memchr(0x1d, after.as_bytes()) {
        Some(i) => (&after[..i], &after[i + 1..]),
        None => (after, ""),
    };
    let exec = r.record_type == "EXECVE";
    let is_path = r.record_type == "PATH";
    let mut s = Scratch::default();

    scan(body, false, &mut |key, value, quoted| match key {
        "pid" => _ = num(value).map(|v| r.pid.get_or_insert(v)),
        "ppid" => _ = num(value).map(|v| r.ppid.get_or_insert(v)),
        "uid" => _ = num(value).map(|v| r.uid.get_or_insert(v)),
        "auid" => _ = num(value).map(|v| r.auid.get_or_insert(v)),
        "euid" => _ = num(value).map(|v| r.euid.get_or_insert(v)),
        "ses" => _ = num(value).map(|v| r.ses.get_or_insert(v)),
        "acct" => put(&mut r.user, value, quoted, true),
        "comm" => put(&mut r.comm, value, quoted, true),
        "exe" => put(&mut r.exe, value, quoted, true),
        "key" => put(&mut r.key, value, quoted, true),
        "cwd" => put(&mut r.cwd, value, quoted, true),
        "name" if is_path => put(&mut r.path, value, quoted, true),
        "cmd" | "proctitle" => {
            if r.command.is_none() {
                r.command = Some(match key {
                    "proctitle" if !quoted => unhex(value, true).map_or(Cow::Borrowed(value), Cow::Owned),
                    _ => text(value, quoted, true),
                });
            }
        }
        "syscall" => _ = r.syscall.get_or_insert(value),
        "success" => s.res = Some(value == "yes"),
        "res" => _ = s.res.get_or_insert(matches!(value, "success" | "1")),
        // `?` is the audit system's "unknown".
        "addr" if value != "?" => _ = r.remote_address.get_or_insert(value),
        "hostname" if value != "?" => _ = r.remote_host.get_or_insert(value),
        "terminal" if value != "?" => _ = r.terminal.get_or_insert(value),
        "op" => _ = r.op.get_or_insert(value),
        "unit" => _ = r.unit.get_or_insert(value),
        "argc" if exec => s.argc = num(value),
        // EXECVE arguments: `aN` whole, `aN_len` its length, `aN[i]` a piece of a long one.
        k if exec && k.starts_with('a') => {
            let digits = k[1..].bytes().take_while(u8::is_ascii_digit).count();
            let (Some(idx), tail) = (num(&k[1..1 + digits]), &k[1 + digits..]) else { return };
            if tail.is_empty() || (tail.starts_with('[') && tail.ends_with(']')) {
                let command = s.command.get_or_insert_with(String::new);
                if s.last_arg != Some(idx) {
                    if s.last_arg.is_some() {
                        command.push(' ');
                    }
                    s.last_arg = Some(idx);
                    s.args += 1;
                }
                command.push_str(&text(value, quoted, true));
            }
        }
        _ => {}
    });
    scan(enriched, false, &mut |key, value, _| match key {
        "AUID" if value != "unset" => _ = s.auid_name.get_or_insert(value),
        "UID" => _ = s.uid_name.get_or_insert(value),
        "SYSCALL" => r.syscall = Some(value),
        _ => {}
    });

    if exec {
        if s.argc.is_some_and(|n| n != s.args) {
            warn(format!("serial {}: EXECVE argc={} but {} arguments found", r.serial, s.argc.unwrap_or(0), s.args));
        }
        r.command = s.command.map(Cow::Owned);
    }
    if r.user.is_none() {
        r.user = s.auid_name.or(s.uid_name).map(Cow::Borrowed);
    }
    r.success = s.res;
    Some(r)
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        if line.bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        // from_utf8 has a faster all-valid path than the chunked lossy decoder.
        let text = std::str::from_utf8(line.bytes).map_or_else(|_| lossy(line.bytes), Cow::Borrowed);
        let mut warnings = Vec::new();
        let record = parse_line(&text, &mut |w| warnings.push(w));
        for w in warnings {
            sink.warn(format!("offset {}: {w}", line.offset));
        }
        match record {
            Some(record) => sink.emit(Loc::Offset(line.offset), &record)?,
            None => sink.warn(format!("offset {}: not an audit record", line.offset)),
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};
    use std::io::Write as _;

    const PATH: &str = "var/log/audit/audit.log";

    fn snap(name: &str) -> String {
        run(&ARTIFACT, PATH, &fixture(&format!("audit-log/{name}")), 0)
    }

    #[test]
    fn parses_every_record_type() {
        insta::assert_snapshot!(snap("audit.log"));
    }

    #[test]
    fn parses_real_enriched_daemon_records() {
        insta::assert_snapshot!(snap("real-enriched.log"));
    }

    #[test]
    fn parses_node_prefix_and_split_execve() {
        insta::assert_snapshot!(snap("node-and-split.log"));
    }

    #[test]
    fn garbage_lines_warn_without_panic() {
        insta::assert_snapshot!(snap("garbage.log"));
    }

    #[test]
    fn empty_file_yields_nothing() {
        insta::assert_snapshot!(run(&ARTIFACT, PATH, b"", 0));
    }

    #[test]
    fn gzip_rotation_matches_plain() {
        let plain = fixture("audit-log/audit.log");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&plain).unwrap();
        let packed = gz.finish().unwrap();
        let name = "var/log/audit/audit.log.2.gz";
        assert_eq!(run(&ARTIFACT, name, &packed, 0), run(&ARTIFACT, name, &plain, 0));
    }

    #[test]
    fn truncated_and_flipped_input_does_not_panic() {
        let data = fixture("audit-log/audit.log");
        for end in (0..data.len()).step_by(7) {
            run(&ARTIFACT, PATH, &data[..end], 0);
        }
        for i in (0..data.len()).step_by(5) {
            let mut copy = data.clone();
            copy[i] ^= 0xff;
            run(&ARTIFACT, PATH, &copy, 0);
        }
    }

    fn on_small_stack(line: Vec<u8>) -> std::time::Duration {
        let t = std::time::Instant::now();
        std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || run(&ARTIFACT, PATH, &line, 0))
            .unwrap()
            .join()
            .unwrap();
        t.elapsed()
    }

    #[test]
    fn nested_msg_quotes_do_not_recurse() {
        let mut line = b"type=USER_LOGIN msg=audit(1700000000.000:1): ".to_vec();
        line.extend_from_slice(&b"msg='".repeat(200_000));
        line.push(b'\n');
        assert!(on_small_stack(line).as_secs() < 5);
    }

    #[test]
    fn unclosed_msg_quote_is_linear() {
        let mut line = b"type=USER_LOGIN msg=audit(1700000000.000:1): msg='".to_vec();
        line.extend_from_slice(&b"a=b ".repeat(250_000));
        line.push(b'\n');
        assert!(on_small_stack(line).as_millis() < 1000);
    }

    #[test]
    fn hex_decoding_rules() {
        assert_eq!(unhex("6C73", false).as_deref(), Some("ls"));
        assert_eq!(unhex("6c7300", true).as_deref(), Some("ls "));
        assert_eq!(unhex("6C7", false), None);
        assert_eq!(unhex("zz", false), None);
        assert_eq!(unhex("", false), None);
    }
}
