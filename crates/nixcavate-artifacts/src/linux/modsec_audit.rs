//! ModSecurity 2 audit log in the serial format (`SecAuditLogType Serial`, the Debian and Red Hat
//! default for Apache): one block per transaction, made of parts introduced by `--<id>-A--` ...
//! `--<id>-Z--`. Format: ModSecurity Reference Manual, "SecAuditLogParts" and "Audit log
//! format". One record per transaction.
//!
//! Read: part A (time, unique id, client and server address), B (the request line, and the
//! `Host`, `User-Agent` and `Referer` headers only), F (the response status line) and H (the
//! `Message:` lines with rule id, message and severity, `Action:` and `Engine-Mode:`).
//! Never read or output: the headers `Authorization`, `Cookie` and `Set-Cookie`, request
//! bodies (part C, I, J) and response bodies (part E), which hold credentials and personal data.
//! The concurrent format (an index file pointing to a tree of files) is not read.

use crate::common::logfmt::cut;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, UNIX};
use nixcavate_core::time::parse_uint;
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "modsec-audit-log",
    "ModSecurity audit log: one record per transaction with the rules that matched",
    Category::Security,
    UNIX,
    &[
        "var/log/apache2/modsec_audit.log*",
        "var/log/httpd/modsec_audit.log*",
        "var/log/modsec_audit.log*",
        "var/log/modsecurity/modsec_audit.log*",
        "var/log/modsecurity/audit.log*",
        "var/log/nginx/modsec_audit.log*",
    ],
    parse,
);

/// Lines kept per part and per transaction; a block that never ends cannot grow without limit.
const MAX_PART_LINES: usize = 2000;

#[derive(Serialize, Default)]
struct Transaction {
    time: Option<Timestamp>,
    unique_id: String,
    client_ip: String,
    client_port: Option<u32>,
    server_ip: String,
    server_port: Option<u32>,
    method: String,
    uri: String,
    protocol: String,
    /// The `Host` request header.
    http_host: Option<String>,
    user_agent: Option<String>,
    referer: Option<String>,
    status: Option<u16>,
    /// Whether ModSecurity blocked the transaction (`Action: Intercepted`).
    intercepted: bool,
    engine_mode: Option<String>,
    /// The rule ids that matched, in the order of the `Message:` lines.
    rule_ids: Vec<String>,
    /// The `msg` of each matching rule, aligned with `rule_ids`.
    rule_messages: Vec<String>,
    /// The `severity` of each matching rule (empty when the rule sets none), aligned with `rule_ids`.
    severities: Vec<String>,
}

impl Record for Transaction {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let kind = if self.intercepted {
            "waf_block"
        } else if self.rule_ids.is_empty() {
            "waf_request"
        } else {
            "waf_alert"
        };
        let message = format!(
            "{} {} {} -> {} rules [{}]",
            self.client_ip,
            self.method,
            cut(&self.uri),
            self.status.unwrap_or(0),
            self.rule_ids.join(",")
        );
        self.time.map(|t| Event::new(t, kind, message)).into_iter()
    }
}

/// `--e76b3671-A--` into the id and the part letter.
fn boundary(line: &str) -> Option<(&str, char)> {
    let inner = line.strip_prefix("--")?.strip_suffix("--")?;
    let (id, part) = inner.rsplit_once('-')?;
    let mut letters = part.chars();
    let (letter, rest) = (letters.next()?, letters.next());
    (rest.is_none() && letter.is_ascii_uppercase() && !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then_some((id, letter))
}

/// `13/Nov/2026:01:35:00.462186 +0000` of part A.
fn part_a_time(text: &str) -> Option<Timestamp> {
    let (whole, zone) = text.split_once(' ')?;
    let (clock, micros) = whole.split_once('.').unwrap_or((whole, ""));
    let utc = crate::common::logfmt::clf_utc(format!("{clock} {zone}").as_bytes())?;
    let digits = micros.len().min(6);
    let frac = parse_uint(micros.get(..digits)?.as_bytes()).unwrap_or(0);
    let nanos = u32::try_from(frac).ok()?.checked_mul(10u32.pow(9 - digits as u32))?;
    Timestamp::checked(utc, nanos, Precision::Micros, Basis::Recorded)
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut current: Option<(u64, String, char, Transaction, usize)> = None;
    let mut seen = false;
    let mut part_lines = 0usize;
    let finish = |current: &mut Option<(u64, String, char, Transaction, usize)>, sink: &mut Sink| -> Result<()> {
        if let Some((line, _, _, transaction, _)) = current.take() {
            sink.emit(Loc::Line(line), &transaction)?;
        }
        Ok(())
    };
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if let Some((id, part)) = boundary(text) {
            part_lines = 0;
            match current.as_mut() {
                Some((_, open, letter, _, _)) if open == id => {
                    *letter = part;
                    if part == 'Z' {
                        finish(&mut current, sink)?;
                    }
                }
                _ => {
                    // A new transaction starts at its A part; anything else is a damaged block.
                    finish(&mut current, sink)?;
                    if part == 'A' {
                        seen = true;
                        current = Some((line.number, id.to_string(), 'A', Transaction::default(), 0));
                    } else {
                        sink.warn(format!("line {}: part {part} of transaction {id} without its part A", line.number));
                    }
                }
            }
            return Ok(());
        }
        let Some((_, _, part, t, request_line_seen)) = current.as_mut() else {
            if !seen && !text.is_empty() {
                return Err(Error::format(
                    "not a serial ModSecurity audit log: the first line is not a `--id-A--` boundary",
                ));
            }
            return Ok(());
        };
        part_lines += 1;
        if part_lines > MAX_PART_LINES || text.is_empty() {
            return Ok(());
        }
        match *part {
            'A' => {
                // `[13/Nov/2026:01:35:00.462186 +0000] uniqueid 127.0.0.1 57050 127.0.0.1 80`
                if let Some((stamp, rest)) = text.strip_prefix('[').and_then(|r| r.split_once("] ")) {
                    t.time = part_a_time(stamp);
                    let mut words = rest.split(' ');
                    t.unique_id = words.next().unwrap_or_default().to_string();
                    t.client_ip = words.next().unwrap_or_default().to_string();
                    t.client_port = words.next().and_then(|p| p.parse().ok());
                    t.server_ip = words.next().unwrap_or_default().to_string();
                    t.server_port = words.next().and_then(|p| p.parse().ok());
                }
            }
            'B' => {
                if *request_line_seen == 0 {
                    *request_line_seen = 1;
                    let mut words = text.splitn(2, ' ');
                    t.method = words.next().unwrap_or_default().to_string();
                    let rest = words.next().unwrap_or_default();
                    match rest.rsplit_once(' ') {
                        Some((uri, protocol)) if protocol.starts_with("HTTP/") => {
                            t.uri = uri.to_string();
                            t.protocol = protocol.to_string();
                        }
                        _ => t.uri = rest.to_string(),
                    }
                } else if let Some((name, value)) = text.split_once(':') {
                    let value = Some(value.trim().to_string());
                    // Only these three headers are ever read; the others may carry credentials.
                    match name.to_ascii_lowercase().as_str() {
                        "host" => t.http_host = value,
                        "user-agent" => t.user_agent = value,
                        "referer" => t.referer = value,
                        _ => {}
                    }
                }
            }
            'F' => {
                if t.status.is_none() && text.starts_with("HTTP/") {
                    t.status = text.split(' ').nth(1).and_then(|s| s.parse().ok());
                }
            }
            'H' => {
                if let Some(message) = text.strip_prefix("Message: ") {
                    t.rule_ids.push(bracketed(message, "id").unwrap_or_default());
                    t.rule_messages.push(bracketed(message, "msg").unwrap_or_else(|| cut(message).to_string()));
                    t.severities.push(bracketed(message, "severity").unwrap_or_default());
                } else if text.starts_with("Action: Intercepted") {
                    t.intercepted = true;
                } else if let Some(mode) = text.strip_prefix("Engine-Mode: ") {
                    t.engine_mode = Some(mode.trim_matches('"').to_string());
                }
            }
            _ => {}
        }
        Ok(())
    })?;
    if let Some((line, id, ..)) = current.as_ref() {
        sink.warn(format!("line {line}: transaction {id} has no part Z (the file ends inside it)"));
    }
    finish(&mut current, sink)?;
    if seen {
        Ok(())
    } else {
        Err(Error::skipped("empty file"))
    }
}

/// The value of `[key "value"]`; the value ends at the first `"` followed by `]`.
fn bracketed(message: &str, key: &str) -> Option<String> {
    let needle = format!("[{key} \"");
    let at = message.find(&needle)? + needle.len();
    let rest = message.get(at..)?;
    let end = rest.find("\"]").unwrap_or(rest.len());
    Some(rest.get(..end)?.replace("\\\"", "\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    fn records(out: &str) -> Vec<&str> {
        out.lines().take_while(|l| !l.starts_with("---")).collect()
    }

    /// Fixture: real Apache 2.4 + ModSecurity 2.9.7 + OWASP CRS 3.3.4 (Debian 12) hit by 7 curl
    /// requests: a clean one, a SQL injection in a query string, a custom rule match, sqlmap's
    /// user agent with UNION SELECT, a path traversal, an XSS POST, and a 404.
    #[test]
    fn one_record_per_transaction_with_the_rules_that_matched() {
        let data = fixture("svclogs/modsec/modsec_audit.log");
        let out = run(&ARTIFACT, "var/log/apache2/modsec_audit.log", &data, 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        let text = String::from_utf8_lossy(&data);
        let transactions = text.lines().filter(|l| l.ends_with("-A--")).count();
        assert_eq!(records(&out).len(), transactions);
        assert_eq!(transactions, 7);
        assert_eq!(
            out.matches("\"intercepted\":true").count(),
            text.lines().filter(|l| l.starts_with("Action: Intercepted")).count()
        );
        let blocked = records(&out).into_iter().find(|l| l.contains("nxblock")).unwrap_or_default();
        assert!(
            blocked.contains("\"status\":403") && blocked.contains("\"900001\"") && blocked.contains("Test rule hit"),
            "{blocked}"
        );
        let sqlmap = records(&out).into_iter().find(|l| l.contains("sqlmap")).unwrap_or_default();
        assert!(
            sqlmap.contains("\"user_agent\":\"sqlmap/1.7\"") && sqlmap.contains("913100") && sqlmap.contains("942"),
            "{sqlmap}"
        );
        // Message lines per transaction: the id and msg arrays line up.
        for line in records(&out) {
            let value: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
            assert_eq!(
                value["rule_ids"].as_array().map(Vec::len),
                value["rule_messages"].as_array().map(Vec::len),
                "{line}"
            );
            assert_eq!(
                value["rule_ids"].as_array().map(Vec::len),
                value["severities"].as_array().map(Vec::len),
                "{line}"
            );
        }
        insta::assert_snapshot!(out);
    }

    #[test]
    fn credentials_and_bodies_are_never_output() {
        let log = "--aaaa1111-A--\n[13/Nov/2026:01:35:00.462186 +0000] id1 10.0.0.9 5555 10.0.0.1 80\n--aaaa1111-B--\nPOST /login HTTP/1.1\nHost: shop.example.test\nAuthorization: Basic c2VjcmV0LXVzZXI6c2VjcmV0LXBhc3M=\nCookie: session=SECRET-COOKIE\nUser-Agent: ua\n\n--aaaa1111-I--\npassword=SECRET-BODY\n--aaaa1111-F--\nHTTP/1.1 302 Found\nSet-Cookie: s=SECRET-SET\n\n--aaaa1111-E--\nSECRET-RESPONSE\n--aaaa1111-H--\nMessage: Warning. x [id \"1\"] [msg \"m\"] [severity \"CRITICAL\"]\n--aaaa1111-Z--\n";
        let out = run(&ARTIFACT, "var/log/apache2/modsec_audit.log", log.as_bytes(), 0);
        for secret in ["c2VjcmV0", "SECRET"] {
            assert!(!out.contains(secret), "{secret} leaked: {out}");
        }
        assert!(out.contains("\"http_host\":\"shop.example.test\"") && out.contains("\"status\":302"), "{out}");
    }

    #[test]
    fn damaged_blocks_are_reported() {
        assert!(run(&ARTIFACT, "var/log/apache2/modsec_audit.log", b"127.0.0.1 - - [x] concurrent index\n", 0)
            .contains("not a serial ModSecurity"));
        let cut = run(
            &ARTIFACT,
            "var/log/apache2/modsec_audit.log",
            b"--abc-A--\n[13/Nov/2026:01:35:00 +0000] i 1.2.3.4 1 5.6.7.8 80\n--abc-B--\nGET / HTTP/1.1\n",
            0,
        );
        assert!(cut.contains("no part Z") && cut.contains("\"uri\":\"/\""), "{cut}");
        assert!(run(&ARTIFACT, "var/log/apache2/modsec_audit.log", b"--abc-B--\nGET / HTTP/1.1\n--abc-Z--\n", 0)
            .contains("without its part A"));
    }

    #[test]
    fn hostile_input_never_panics() {
        let full = fixture("svclogs/modsec/modsec_audit.log");
        let mut seed = 3u64;
        for cut in (0..full.len()).step_by(17) {
            run(&ARTIFACT, "var/log/apache2/modsec_audit.log", &full[..cut], 0);
        }
        for _ in 0..500 {
            let mut copy = full[..6000.min(full.len())].to_vec();
            for _ in 0..4 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let at = (seed >> 33) as usize % copy.len();
                copy[at] = (seed >> 20) as u8;
            }
            run(&ARTIFACT, "var/log/apache2/modsec_audit.log", &copy, 0);
        }
    }
}
