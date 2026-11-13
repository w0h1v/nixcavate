//! Mail server logs as files: Postfix and Dovecot lines in `mail.log`/`maillog`/`mail.info`
//! (the syslog layouts of `common::syslog`), Dovecot's own `dovecot.log`, and the Exim
//! `mainlog`. The same lines also reach the generic `syslog` artifact; this one knows what
//! they mean.
//!
//! Formats: Postfix `postfix/smtpd`, `qmgr`, `local`, `smtp` logging (postconf(5), the
//! documented `QUEUE-ID: key=value, ...` lines); Dovecot login-process messages
//! (`imap-login: Login: user=<u>, method=PLAIN, rip=...`); Exim `mainlog` (Exim specification,
//! chapter 49 "Log files": `<=` arrival, `=>`/`->` delivery, `**` failure, `==` deferral).
//!
//! Records are the lines that say who connected, authenticated, sent or received; connection
//! chatter (`connect from`, `disconnect from`, `removed`) is not a record. A Postfix queue id
//! ties the client and sender of one message to its delivery lines, so `mail_sent` records
//! carry the client address and the SASL user even though those were logged lines earlier.
//! The table holding that tie is capped; past the cap it is dropped and one warning says so.

use crate::common::logfmt::{cut, field};
use crate::common::syslog::{parse_header, timeline_message};
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, UNIX};
use nixcavate_core::time::{parse_iso8601, parse_uint};
use nixcavate_core::{Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashMap;

pub const ARTIFACT: Artifact = Artifact::new(
    "mail-log",
    "Postfix, Dovecot and Exim mail logs: logins, authentication failures, mail in and out",
    Category::Logs,
    UNIX,
    &[
        "var/log/mail.log*",
        "var/log/maillog*",
        "var/log/mail.info*",
        "var/log/mail.warn*",
        "var/log/mail.err*",
        "var/log/exim4/mainlog*",
        "var/log/exim/main.log*",
        "var/log/exim/mainlog*",
        "var/log/dovecot.log*",
        "var/log/dovecot-info.log*",
    ],
    parse,
);

/// Queue ids remembered at once; real queues are far smaller than this.
const MAX_QUEUE_IDS: usize = 200_000;

#[derive(Serialize)]
struct Mail<'a> {
    time: Option<Timestamp>,
    log_host: &'a str,
    /// `postfix`, `dovecot` or `exim`.
    service: &'static str,
    /// `mail_login`, `mail_auth_failure`, `mail_sent`, `mail_received`, `mail_failed`
    /// (deferred or bounced delivery) or `mail_rejected`.
    event: &'static str,
    queue_id: Option<&'a str>,
    from: Option<Cow<'a, str>>,
    to: Option<&'a str>,
    /// The next hop of a delivery: `local`, `mx.example[192.0.2.1]:25`, an Exim transport.
    relay: Option<&'a str>,
    status: Option<&'a str>,
    client_host: Option<Cow<'a, str>>,
    client_ip: Option<Cow<'a, str>>,
    /// The account that logged in or authenticated (never a password).
    user: Option<Cow<'a, str>>,
    /// `imap`, `pop3`, `smtp` or the SASL/Exim authenticator.
    method: Option<&'a str>,
    size: Option<u64>,
    /// The reason or the rest of the line that matters, cut at 300 bytes.
    detail: &'a str,
}

impl Record for Mail<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who = self.user.as_deref().or(self.from.as_deref()).unwrap_or_default();
        let target = self.to.or(self.client_ip.as_deref()).unwrap_or_default();
        let message = || timeline_message(self.service, &format!("{} {who} {target} {}", self.event, self.detail));
        self.time.map(|t| Event::new(t, self.event, message())).into_iter()
    }
}

/// `host[ip]` into the two parts; text without brackets is the host alone.
fn host_ip(text: &str) -> (&str, Option<&str>) {
    match text.split_once('[') {
        Some((host, rest)) => (host, rest.split(']').next()),
        None => (text, None),
    }
}

#[derive(Default)]
struct Context {
    client_host: String,
    client_ip: String,
    user: String,
    from: String,
}

struct State {
    queue: HashMap<String, Context>,
    warned: bool,
}

fn blank<'a>(time: Option<Timestamp>, log_host: &'a str, service: &'static str, event: &'static str) -> Mail<'a> {
    Mail {
        time,
        log_host,
        service,
        event,
        queue_id: None,
        from: None,
        to: None,
        relay: None,
        status: None,
        client_host: None,
        client_ip: None,
        user: None,
        method: None,
        size: None,
        detail: "",
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let name = input.path.rsplit('/').next().unwrap_or_default();
    let exim = input.path.contains("/exim");
    let native_dovecot = name.starts_with("dovecot");
    let mut state = State { queue: HashMap::new(), warned: false };
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        let at = Loc::Line(line.number);
        if exim {
            return exim_line(input, sink, at, text);
        }
        if native_dovecot {
            return dovecot_native_line(input, sink, at, text);
        }
        let header = parse_header(input, text.as_bytes());
        if header.program.starts_with("postfix") {
            postfix_line(sink, at, &mut state, header.time, &header.log_host, &header.message)
        } else if header.program == "dovecot" {
            dovecot_message(sink, at, header.time, &header.log_host, &header.message)
        } else {
            Ok(())
        }
    })
}

fn postfix_line(
    sink: &mut Sink,
    at: Loc,
    state: &mut State,
    time: Option<Timestamp>,
    log_host: &str,
    message: &str,
) -> Result<()> {
    // `warning: host[ip]: SASL PLAIN authentication failed: reason, sasl_username=alice`
    if let Some(rest) = message.strip_prefix("warning: ") {
        let Some((client, rest)) = rest.split_once(": SASL ") else { return Ok(()) };
        let Some((method, reason)) = rest.split_once(" authentication failed") else { return Ok(()) };
        let (host, ip) = host_ip(client);
        let mut mail = blank(time, log_host, "postfix", "mail_auth_failure");
        mail.client_host = Some(Cow::Borrowed(host));
        mail.client_ip = ip.map(Cow::Borrowed);
        mail.user = field(reason, "sasl_username=").map(Cow::Borrowed);
        mail.method = Some(method);
        mail.detail = cut(reason.trim_start_matches(": "));
        return sink.emit(at, &mail);
    }
    let Some((id, rest)) = message.split_once(": ") else { return Ok(()) };
    if id.len() < 5 || id.len() > 20 || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Ok(());
    }
    if let Some(rest) = rest.strip_prefix("reject: ") {
        // `NOQUEUE: reject: RCPT from host[ip]: 550 5.1.1 <x>: reason; from=<a> to=<b> proto=ESMTP`
        let (stage_and_client, reason) = rest.split_once(": ").unwrap_or((rest, ""));
        let client = stage_and_client.rsplit(' ').next().unwrap_or_default();
        let (host, ip) = host_ip(client);
        let mut mail = blank(time, log_host, "postfix", "mail_rejected");
        mail.queue_id = Some(id).filter(|id| *id != "NOQUEUE");
        mail.from = field(reason, "from=").map(Cow::Borrowed);
        mail.to = field(reason, "to=");
        mail.client_host = Some(Cow::Borrowed(host));
        mail.client_ip = ip.map(Cow::Borrowed);
        mail.status = Some("reject");
        mail.method = field(reason, "proto=");
        mail.detail = cut(reason.split(';').next().unwrap_or_default());
        return sink.emit(at, &mail);
    }
    if rest == "removed" {
        state.queue.remove(id);
        return Ok(());
    }
    if let Some(uid) = rest.strip_prefix("uid=") {
        // `pickup`: a message submitted locally (`sendmail`, cron): the numeric uid is who sent it.
        if state.queue.len() >= MAX_QUEUE_IDS {
            state.queue.clear();
        }
        let entry = state.queue.entry(id.to_string()).or_default();
        entry.user = format!("uid={}", uid.split(' ').next().unwrap_or_default());
        entry.client_host = "local".to_string();
        return Ok(());
    }
    if let Some(client) = rest.strip_prefix("client=") {
        // smtpd accepted a message into the queue: remember who sent it.
        if state.queue.len() >= MAX_QUEUE_IDS {
            state.queue.clear();
            if !std::mem::replace(&mut state.warned, true) {
                sink.warn(format!(
                    "more than {MAX_QUEUE_IDS} queue ids at once: client details of older messages are lost"
                ));
            }
        }
        let (host, ip) = host_ip(client.split(',').next().unwrap_or_default());
        let entry = state.queue.entry(id.to_string()).or_default();
        entry.client_host = host.to_string();
        entry.client_ip = ip.unwrap_or_default().to_string();
        entry.user = field(client, "sasl_username=").unwrap_or_default().to_string();
        return Ok(());
    }
    if let Some(from) = field(rest, "from=").filter(|_| rest.starts_with("from=")) {
        let ctx = state.queue.get(id);
        let mut mail = blank(time, log_host, "postfix", "mail_received");
        mail.queue_id = Some(id);
        mail.from = Some(Cow::Borrowed(from));
        mail.size = field(rest, "size=").and_then(|s| parse_uint(s.as_bytes()));
        mail.detail = rest.split_once(", ").map_or("", |(_, tail)| cut(tail));
        fill_client(&mut mail, ctx);
        let record_from = from.to_string();
        sink.emit(at, &mail)?;
        state.queue.entry(id.to_string()).or_default().from = record_from;
        return Ok(());
    }
    if let Some(to) = field(rest, "to=").filter(|_| rest.starts_with("to=")) {
        let status = field(rest, "status=");
        let ctx = state.queue.get(id);
        let mut mail =
            blank(time, log_host, "postfix", if status == Some("sent") { "mail_sent" } else { "mail_failed" });
        mail.queue_id = Some(id);
        mail.to = Some(to);
        mail.relay = field(rest, "relay=");
        mail.status = status;
        mail.method = field(rest, "dsn=");
        mail.detail = rest.split_once("status=").map_or("", |(_, tail)| cut(tail));
        if let Some(ctx) = ctx {
            mail.from = Some(Cow::Borrowed(ctx.from.as_str())).filter(|f| !f.is_empty());
        }
        fill_client(&mut mail, ctx);
        return sink.emit(at, &mail);
    }
    Ok(())
}

fn fill_client<'a>(mail: &mut Mail<'a>, ctx: Option<&'a Context>) {
    let Some(ctx) = ctx else { return };
    let some = |s: &'a String| (!s.is_empty()).then_some(Cow::Borrowed(s.as_str()));
    mail.client_host = some(&ctx.client_host);
    mail.client_ip = some(&ctx.client_ip);
    mail.user = some(&ctx.user);
}

/// A Dovecot message as syslog carries it: `imap-login: Login: user=<alice>, method=PLAIN, ...`.
fn dovecot_message(sink: &mut Sink, at: Loc, time: Option<Timestamp>, log_host: &str, message: &str) -> Result<()> {
    let Some((process, rest)) = message.split_once(": ") else { return Ok(()) };
    let Some(protocol) = process.strip_suffix("-login") else { return Ok(()) };
    let (event, status) = if rest.starts_with("Login: ") {
        ("mail_login", "ok")
    } else if rest.contains("(auth failed") && (rest.starts_with("Disconnected") || rest.starts_with("Aborted login")) {
        ("mail_auth_failure", "auth failed")
    } else {
        return Ok(());
    };
    let mut mail = blank(time, log_host, "dovecot", event);
    mail.client_ip = field(rest, "rip=").map(Cow::Borrowed);
    mail.user = field(rest, "user=").filter(|u| !u.is_empty()).map(Cow::Borrowed);
    mail.method = Some(protocol);
    mail.status = Some(status);
    mail.relay = field(rest, "method=");
    mail.detail = match rest.split_once('(') {
        Some((_, inner)) if event == "mail_auth_failure" => cut(inner.split(')').next().unwrap_or_default()),
        _ => cut(rest.split_once(": ").map_or(rest, |(_, tail)| tail)),
    };
    sink.emit(at, &mail)
}

/// `Mar 10 01:02:03 imap-login: Info: Login: ...` or the same with an ISO date, as written by
/// `log_path` in `dovecot.conf`.
fn dovecot_native_line(input: &Input, sink: &mut Sink, at: Loc, text: &str) -> Result<()> {
    let (time, rest) = match parse_iso8601(text.as_bytes()) {
        Some((parsed, used)) => (Some(crate::common::stamped_log::timestamp(input, &parsed)), text.get(used..)),
        None => (parse_header(input, text.as_bytes()).time, text.get(16..)),
    };
    let Some(rest) = rest.map(str::trim_start) else { return Ok(()) };
    let Some((process, tail)) = rest.split_once(": ") else { return Ok(()) };
    let tail = ["Info: ", "Warning: ", "Error: ", "Debug: "].iter().find_map(|l| tail.strip_prefix(l)).unwrap_or(tail);
    let message = format!("{process}: {tail}");
    dovecot_message(sink, at, time, "", &message)
}

/// The 16-character Exim message id (`1rjXyZ-0001Ab-3x`): six, six and two alphanumerics.
fn exim_id(text: &str) -> Option<&str> {
    let id = text.get(..16)?;
    let ok = id.bytes().enumerate().all(|(i, b)| if i == 6 || i == 13 { b == b'-' } else { b.is_ascii_alphanumeric() });
    (ok && matches!(text.as_bytes().get(16), Some(b' ') | None)).then_some(id)
}

fn exim_line(input: &Input, sink: &mut Sink, at: Loc, text: &str) -> Result<()> {
    let Some((parsed, used)) = parse_iso8601(text.as_bytes()) else { return Ok(()) };
    let time = Some(crate::common::stamped_log::timestamp(input, &parsed));
    let Some(rest) = text.get(used..).map(str::trim_start) else { return Ok(()) };
    if let Some(id) = exim_id(rest) {
        let body = rest.get(17..).unwrap_or_default();
        let (flag, body) = body.split_once(' ').unwrap_or((body, ""));
        return match flag {
            "<=" => {
                let (sender, tail) = body.split_once(' ').unwrap_or((body, ""));
                let mut mail = blank(time, "", "exim", "mail_received");
                mail.queue_id = Some(id);
                mail.from = Some(Cow::Borrowed(sender));
                let (host, ip) = exim_host(tail);
                mail.client_host = Some(Cow::Borrowed(host)).filter(|h| !h.is_empty());
                mail.client_ip = ip.map(Cow::Borrowed);
                let authenticated = field(tail, "A=").map(|a| a.split_once(':').unwrap_or((a, "")));
                mail.user = authenticated.map(|(_, user)| user).or_else(|| field(tail, "U=")).map(Cow::Borrowed);
                mail.method = field(tail, "P=");
                mail.relay = authenticated.map(|(authenticator, _)| authenticator);
                mail.size = field(tail, "S=").and_then(|s| parse_uint(s.as_bytes()));
                mail.detail = cut(tail);
                sink.emit(at, &mail)
            }
            "=>" | "->" | "**" | "==" => {
                let event = match flag {
                    "=>" | "->" => "mail_sent",
                    _ => "mail_failed",
                };
                // `alice <alice@host> R=router T=transport H=host [ip]`: the address in angle
                // brackets when there is one, else the first token.
                let address = match (body.find('<'), body.find('>')) {
                    (Some(open), Some(close)) if open < close => body.get(open + 1..close),
                    _ => body.split([' ', ':']).next(),
                };
                let mut mail = blank(time, "", "exim", event);
                mail.queue_id = Some(id);
                mail.to = address;
                let (host, ip) = exim_host(body);
                mail.relay = field(body, "T=").or(Some(host).filter(|h| !h.is_empty()));
                mail.client_ip = ip.map(Cow::Borrowed);
                mail.status = Some(match flag {
                    "=>" => "delivered",
                    "->" => "delivered (additional recipient)",
                    "**" => "failed",
                    _ => "deferred",
                });
                mail.detail = cut(body);
                sink.emit(at, &mail)
            }
            _ => Ok(()),
        };
    }
    // `login authenticator failed for (helo) [192.0.2.1]: 535 Incorrect authentication data (set_id=alice)`
    if let Some((authenticator, tail)) = rest.split_once(" authenticator failed for ") {
        if !authenticator.contains(' ') {
            let hosted = format!("H={tail}");
            let (host, ip) = exim_host(&hosted);
            let mut mail = blank(time, "", "exim", "mail_auth_failure");
            mail.client_host = (!host.is_empty()).then(|| Cow::Owned(host.to_string()));
            mail.client_ip = ip.map(|i| Cow::Owned(i.to_string()));
            mail.user = tail.split("set_id=").nth(1).map(|u| Cow::Owned(u.trim_end_matches(')').to_string()));
            mail.method = Some(authenticator);
            mail.detail = cut(tail.split_once("]: ").map_or(tail, |(_, reason)| reason));
            return sink.emit(at, &mail);
        }
    }
    // `H=host [192.0.2.1] F=<a> rejected RCPT <b>: reason`
    if let Some((before, after)) = rest.split_once(" rejected ") {
        if after.starts_with("RCPT ") || after.starts_with("MAIL ") || after.starts_with("connection") {
            let (host, ip) = exim_host(before);
            let mut mail = blank(time, "", "exim", "mail_rejected");
            mail.client_host = Some(Cow::Borrowed(host)).filter(|h| !h.is_empty());
            mail.client_ip = ip.map(Cow::Borrowed);
            mail.from = field(before, "F=").map(Cow::Borrowed);
            mail.status = Some("reject");
            mail.detail = cut(after);
            return sink.emit(at, &mail);
        }
    }
    Ok(())
}

/// The `H=` part of an Exim line: `H=host (helo) [ip]`, `H=(helo) [ip]` or `H=[ip]`.
fn exim_host(text: &str) -> (&str, Option<&str>) {
    let Some(start) = text.find("H=") else { return ("", None) };
    let rest = &text[start + 2..];
    let host = rest.split([' ', '[']).next().unwrap_or_default();
    let host = if host.starts_with('(') { "" } else { host };
    let ip = rest.split_once('[').and_then(|(_, tail)| tail.split(']').next());
    (host, ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    fn count(out: &str, event: &str) -> usize {
        out.lines()
            .take_while(|l| !l.starts_with("---"))
            .filter(|l| l.contains(&format!("\"event\":\"{event}\"")))
            .count()
    }

    /// Fixture: real Postfix 3.7.11 and Dovecot 2.3.19 (Debian 12) driven by smtplib, imaplib and
    /// poplib: 3 messages accepted, 1 recipient and 1 relay attempt rejected, 4 deliveries,
    /// 3 logins, 1 failed IMAP login, and 2 failed SMTP logins tried with PLAIN and LOGIN.
    #[test]
    fn postfix_and_dovecot_match_what_the_clients_did() {
        let data = fixture("svclogs/postfix-dovecot/mail.log");
        let out = run(&ARTIFACT, "var/log/mail.log", &data, 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        let text = String::from_utf8_lossy(&data);
        let lines = |needle: &str| text.lines().filter(|l| l.contains(needle)).count();
        assert_eq!(count(&out, "mail_login"), lines("-login: Login: user="));
        assert_eq!(count(&out, "mail_login"), 3);
        assert_eq!(count(&out, "mail_auth_failure"), lines("authentication failed:") + lines("(auth failed"));
        assert_eq!(count(&out, "mail_auth_failure"), 5);
        assert_eq!(count(&out, "mail_sent"), lines("status=sent"));
        assert_eq!(count(&out, "mail_sent"), 4);
        assert_eq!(count(&out, "mail_received"), lines("nrcpt="));
        assert_eq!(count(&out, "mail_received"), 3);
        assert_eq!(count(&out, "mail_rejected"), 2);
        // The queue id carries the client and SASL user from the smtpd line to the delivery.
        let authed = out
            .lines()
            .find(|l| l.contains("\"queue_id\":\"94E35DD77583\"") && l.contains("mail_sent"))
            .unwrap_or_default();
        assert!(authed.contains("\"user\":\"alice\"") && authed.contains("\"client_ip\":\"127.0.0.1\""), "{authed}");
        assert!(authed.contains("\"from\":\"alice@mail.example.test\""), "{authed}");
        insta::assert_snapshot!(out);
    }

    /// Dovecot's own `log_path` file: no host, `Info:` after the process.
    #[test]
    fn dovecot_native_log() {
        let out = run(&ARTIFACT, "var/log/dovecot.log", &fixture("svclogs/postfix-dovecot/dovecot.log"), 1_800_000_000);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        assert_eq!((count(&out, "mail_login"), count(&out, "mail_auth_failure")), (2, 1), "{out}");
        assert!(out.contains("\"user\":\"bob\"") && out.contains("\"time\":\"2026-11-13T01:15:12Z\""), "{out}");
    }

    /// Fixture: real Exim 4.96 (Debian 12) driven by smtplib: 7 messages received over SMTP, 1 local, 2
    /// bounces generated by Exim itself (`<> R=`), 5 delivered local recipients, 4 `**` failures.
    #[test]
    fn exim_mainlog_matches_what_the_clients_did() {
        let data = fixture("svclogs/exim/mainlog");
        let out = run(&ARTIFACT, "var/log/exim4/mainlog", &data, 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        let text = String::from_utf8_lossy(&data);
        let lines = |needle: &str| text.lines().filter(|l| l.contains(needle)).count();
        assert_eq!(count(&out, "mail_received"), lines(" <= "));
        assert_eq!(count(&out, "mail_sent"), lines(" => ") + lines(" -> "));
        assert_eq!(count(&out, "mail_failed"), lines(" ** ") + lines(" == "));
        assert_eq!(count(&out, "mail_received"), 9);
        assert_eq!(count(&out, "mail_sent"), 6);
        assert_eq!(count(&out, "mail_failed"), 4);
        assert!(
            out.contains("\"client_host\":\"localhost\",\"client_ip\":\"127.0.0.1\"") && out.contains("\"size\":347"),
            "{out}"
        );
        assert!(out.contains("\"to\":\"alice@mail.example.test\",\"relay\":\"mail_spool\""), "{out}");
        assert!(
            out.contains("\"status\":\"failed\",\"client_host\":null") && out.contains("Unrouteable address"),
            "{out}"
        );
        insta::assert_snapshot!(out);
    }

    /// Synthetic only (the Debian build in the fixture did not advertise AUTH): lines as the Exim
    /// specification's log chapter shows them for an authenticated arrival and failed authentications.
    #[test]
    fn exim_authenticator_lines_synthetic() {
        let log = b"2024-03-10 01:02:03 1rjXyZ-0001Ab-3x <= bob@example.test H=(client) [192.0.2.7] P=esmtpsa A=login:bob S=328 id=abc@example\n\
2024-03-10 01:02:04 login authenticator failed for (client) [192.0.2.7]: 535 Incorrect authentication data (set_id=mallory)\n\
2024-03-10 01:02:05 H=bad.example [192.0.2.9] F=<x@y> rejected RCPT <z@mail.example.test>: relay not permitted\n";
        let out = run(&ARTIFACT, "var/log/exim4/mainlog", log, 0);
        assert!(out.contains("\"user\":\"bob\"") && out.contains("\"relay\":\"login\""), "{out}");
        assert!(out.contains("mail_auth_failure") && out.contains("\"user\":\"mallory\""), "{out}");
        assert!(out.contains("mail_rejected") && out.contains("\"client_ip\":\"192.0.2.9\""), "{out}");
    }

    /// Real Postfix 2.10.1 (CentOS 7) from a scripted guest: `pickup` names the local uid.
    #[test]
    fn local_submissions_name_the_uid() {
        let log = "Nov 12 21:45:01 h postfix/pickup[1]: 263474220A4: uid=0 from=<root>\nNov 12 21:45:01 h postfix/qmgr[1]: 263474220A4: from=<root@h.localdomain>, size=1062, nrcpt=1 (queue active)\nNov 12 21:45:01 h postfix/local[2]: 263474220A4: to=<root@h.localdomain>, orig_to=<root>, relay=local, delay=0.06, delays=0.04/0.01/0/0.01, dsn=2.0.0, status=sent (delivered to mailbox)\nNov 12 21:45:01 h postfix/qmgr[1]: 263474220A4: removed\n";
        let out = run(&ARTIFACT, "var/log/maillog", log.as_bytes(), 1_800_000_000);
        assert_eq!(count(&out, "mail_received") + count(&out, "mail_sent"), 2, "{out}");
        assert!(out.matches("\"user\":\"uid=0\"").count() == 2 && out.contains("\"client_host\":\"local\""), "{out}");
    }

    #[test]
    fn classic_syslog_layout_gives_the_same_records() {
        let iso = run(&ARTIFACT, "var/log/mail.log", &fixture("svclogs/postfix-dovecot/mail.log"), 1_800_000_000);
        let classic =
            run(&ARTIFACT, "var/log/mail.info", &fixture("svclogs/postfix-dovecot/mail.classic"), 1_800_000_000);
        for event in ["mail_login", "mail_auth_failure", "mail_sent", "mail_received", "mail_rejected"] {
            assert_eq!(count(&iso, event), count(&classic, event), "{event}");
        }
    }

    #[test]
    fn no_password_appears_in_the_output() {
        let out = run(&ARTIFACT, "var/log/mail.log", &fixture("svclogs/postfix-dovecot/mail.log"), 0);
        assert!(!out.contains("Example-Pass") && !out.contains("wrong-pass"));
    }

    #[test]
    fn hostile_lines_never_panic() {
        let cases: [&[u8]; 8] = [
            b"2024-03-10T01:02:03+00:00 h postfix/qmgr[1]: ABCDEF: from=<",
            b"2024-03-10T01:02:03+00:00 h postfix/smtpd[1]: warning: [: SASL  authentication failed",
            b"2024-03-10T01:02:03+00:00 h dovecot: imap-login: Login: user=<",
            b"2024-03-10T01:02:03+00:00 h postfix/smtpd[1]: NOQUEUE: reject: RCPT from : ;",
            b"Mar 10 01:02:03 h dovecot: pop3-login: Aborted login (auth failed, user=<\xff",
            b"\xff\xfe\n\n\x00\x00",
            b"2024-03-10T01:02:03+00:00 h postfix/local[1]: ABCDEF: to=<x>, relay=, status=",
            b"2024-03-10T01:02:03+00:00 h postfix/smtpd[1]: ABCDEF: client=[",
        ];
        for data in cases {
            for path in ["var/log/mail.log", "var/log/exim4/mainlog", "var/log/dovecot.log"] {
                run(&ARTIFACT, path, data, 1_700_000_000);
            }
        }
        let full = fixture("svclogs/postfix-dovecot/mail.log");
        for cut in (0..full.len()).step_by(37) {
            run(&ARTIFACT, "var/log/mail.log", &full[..cut], 0);
        }
        // Byte flips.
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..3000 {
            let mut copy = full[..3000.min(full.len())].to_vec();
            for _ in 0..4 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let at = (seed >> 33) as usize % copy.len();
                copy[at] = (seed >> 20) as u8;
            }
            run(&ARTIFACT, "var/log/mail.log", &copy, 0);
        }
    }
}
