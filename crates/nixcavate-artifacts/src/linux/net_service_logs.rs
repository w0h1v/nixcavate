//! Logs and state files of network services:
//!
//! - BIND `named` query log: `13-Nov-2026 01:16:32.281 queries: info: client @0x7f 192.0.2.1#53000
//!   (example.com): query: example.com IN A +E(0)K (192.0.2.53)` (BIND 9 Administrator Reference
//!   Manual, "query logging"; the `print-time`, `print-category` and `print-severity` options).
//! - fail2ban `fail2ban.log`: `2024-03-10 01:02:03,123 fail2ban.actions [123]: NOTICE [sshd] Ban 192.0.2.1`.
//! - ISC `dhcpd.leases` (dhcpd.leases(5)) and `dhclient.leases` (dhclient.leases(5)).
//!
//! DHCP lease times are UTC unless the server was configured with `db-time-format local`, which
//! writes no zone: such a file is read as UTC, as ISC's own tools do by default.

use crate::common::logfmt::{cut, Unparsed};
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, UNIX};
use nixcavate_core::time::{month_from_abbrev, parse_iso8601, parse_uint, secs_from_civil};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const NAMED: Artifact = Artifact::new(
    "named-query-log",
    "BIND named query log: who asked for which name",
    Category::Network,
    UNIX,
    &[
        "var/log/named/*",
        "var/log/bind/*",
        "var/named/*.log*",
        "var/named/data/*.log*",
        "var/log/named.log*",
        "var/log/bind9/*",
    ],
    parse_named,
)
.split_lines();

pub const FAIL2BAN: Artifact = Artifact::new(
    "fail2ban-log",
    "fail2ban log: failures found, bans and unbans",
    Category::Security,
    UNIX,
    &["var/log/fail2ban.log*", "var/log/fail2ban/fail2ban.log*"],
    parse_fail2ban,
);

pub const DHCPD_LEASES: Artifact = Artifact::new(
    "dhcpd-leases",
    "ISC DHCP server lease database",
    Category::Network,
    UNIX,
    &[
        "var/lib/dhcp/dhcpd.leases*",
        "var/lib/dhcpd/dhcpd.leases*",
        "var/lib/dhcp3/dhcpd.leases*",
        "var/db/dhcpd.leases*",
    ],
    parse_dhcpd,
);

pub const DHCLIENT_LEASES: Artifact = Artifact::new(
    "dhclient-leases",
    "ISC DHCP client leases (dhclient, NetworkManager's dhclient)",
    Category::Network,
    UNIX,
    &[
        "var/lib/dhcp/dhclient*.leases*",
        "var/lib/dhclient/*.leases*",
        "var/lib/dhcp3/dhclient*.leases*",
        "var/lib/NetworkManager/dhclient-*.lease*",
        "var/db/dhclient.leases*",
    ],
    parse_dhclient,
);

// ---- named ----

#[derive(Serialize)]
struct Query<'a> {
    time: Option<Timestamp>,
    client_ip: &'a str,
    client_port: Option<u32>,
    /// The name as written in the client's message (`(name)`), not lower-cased.
    qname: &'a str,
    qclass: &'a str,
    qtype: &'a str,
    /// `+` recursion desired, `-` not, `E(0)` EDNS version, `T` TCP, `D` DO bit, `C` CD bit, `K` cookie.
    flags: &'a str,
    /// The local address that was asked.
    server_ip: &'a str,
    view: Option<&'a str>,
}

impl Record for Query<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("{} asked {} {} {}", self.client_ip, cut(self.qname), self.qclass, self.qtype);
        self.time.map(|t| Event::new(t, "dns_query", message)).into_iter()
    }
}

/// `13-Nov-2026 01:16:32.281` (BIND's default) or an ISO time (`print-time iso8601`).
fn named_time(input: &Input, text: &str) -> Option<(Timestamp, usize)> {
    let b = text.as_bytes();
    if b.get(2) == Some(&b'-') && b.get(6) == Some(&b'-') {
        let num = |from: usize, len: usize| parse_uint(b.get(from..from + len)?).and_then(|v| u32::try_from(v).ok());
        let wall = secs_from_civil(
            i64::from(num(7, 4)?),
            month_from_abbrev(b.get(3..6)?)?,
            num(0, 2)?,
            num(12, 2)?,
            num(15, 2)?,
            num(18, 2)?,
        )?;
        let (nanos, precision, used) = match b.get(20) {
            Some(b'.') => {
                let digits = b.get(21..)?.iter().take_while(|d| d.is_ascii_digit()).count().min(9);
                let frac = parse_uint(b.get(21..21 + digits)?)?;
                (u32::try_from(frac).ok()?.checked_mul(10u32.pow(9 - digits as u32))?, Precision::Millis, 21 + digits)
            }
            _ => (0, Precision::Seconds, 20),
        };
        return Some((input.local_time(wall, nanos, precision), used));
    }
    let (parsed, used) = parse_iso8601(b)?;
    Some((crate::common::stamped_log::timestamp(input, &parsed), used))
}

fn parse_named(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut unparsed = Unparsed::default();
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        // Other categories may share the file; only `queries` are records.
        let Some((time, used)) = named_time(input, text) else {
            if !text.is_empty() {
                unparsed.note(line.number);
            }
            return Ok(());
        };
        let rest = text.get(used..).unwrap_or_default().trim_start();
        let Some((_, query)) = rest.split_once(" query: ") else { return Ok(()) };
        let Some(head) = rest.get(..rest.len() - query.len()).and_then(|h| h.split_once("client ")) else {
            return Ok(());
        };
        // `@0x7f..` (BIND 9.10+), the client address `ip#port`, `(name)`, optionally `view x:`.
        let mut words = head.1.split(' ');
        let first = words.next().unwrap_or_default();
        let who = if first.starts_with('@') { words.next().unwrap_or_default() } else { first };
        let (ip, port) = who.split_once('#').unwrap_or((who, ""));
        let view = head.1.split_once(" view ").map(|(_, v)| v.split(':').next().unwrap_or_default());
        let mut q = query.split(' ');
        let (qname, qclass, qtype, flags, server) = (q.next(), q.next(), q.next(), q.next(), q.next());
        let (Some(qname), Some(qclass), Some(qtype), Some(flags)) = (qname, qclass, qtype, flags) else {
            unparsed.note(line.number);
            return Ok(());
        };
        let name_in_parens = head.1.split_once('(').and_then(|(_, n)| n.split_once("):")).map_or(qname, |(n, _)| n);
        sink.emit(
            Loc::Offset(line.offset),
            &Query {
                time: Some(time),
                client_ip: ip,
                client_port: port.parse().ok(),
                qname: name_in_parens,
                qclass,
                qtype,
                flags,
                server_ip: server.map_or("", |s| s.trim_start_matches('(').trim_end_matches(')')),
                view,
            },
        )
    })?;
    unparsed.report(sink, "named query log");
    Ok(())
}

// ---- fail2ban ----

#[derive(Serialize)]
struct Fail2ban<'a> {
    time: Option<Timestamp>,
    /// `fail2ban.actions`, `fail2ban.filter`, `fail2ban.server`...
    component: &'a str,
    pid: Option<u32>,
    level: &'a str,
    jail: Option<&'a str>,
    /// `Found`, `Ban`, `Unban`, `Restore Ban`, `already banned` or `Ignore`; empty for other lines.
    action: Option<&'static str>,
    ip: Option<&'a str>,
    message: &'a str,
}

impl Record for Fail2ban<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let kind = match self.action {
            Some("Found") => "f2b_found",
            Some("Ban" | "Restore Ban") => "f2b_ban",
            Some("Unban") => "f2b_unban",
            _ => return None.into_iter(),
        };
        let message = format!(
            "[{}] {} {}",
            self.jail.unwrap_or("-"),
            self.action.unwrap_or_default(),
            self.ip.unwrap_or_default()
        );
        self.time.map(|t| Event::new(t, kind, message)).into_iter()
    }
}

fn fail2ban_entry<'a>(input: &Input, text: &'a str) -> Option<Fail2ban<'a>> {
    let (parsed, used) = parse_iso8601(text.as_bytes())?;
    let time = crate::common::stamped_log::timestamp(input, &parsed);
    let rest = text.get(used..)?.trim_start();
    // `fail2ban.actions        [4218]: NOTICE  [sshd] Ban 1.2.3.4` or `fail2ban.actions: WARNING ...`
    let (head, body) = rest.split_once(": ")?;
    let (component, pid) = match head.split_once('[') {
        Some((component, pid)) => {
            (component.trim_end(), parse_uint(pid.trim_end_matches(']').as_bytes()).and_then(|p| u32::try_from(p).ok()))
        }
        None => (head.trim_end(), None),
    };
    let (level, body) = body.trim_start().split_once(' ').unwrap_or((body, ""));
    let body = body.trim_start();
    let (jail, action_text) = match body.strip_prefix('[').and_then(|b| b.split_once("] ")) {
        Some((jail, rest)) => (Some(jail), rest),
        None => (None, body),
    };
    let first = |word: &'static str| {
        action_text
            .strip_prefix(word)
            .and_then(|r| r.strip_prefix(' '))
            .map(|r| r.split(' ').next().unwrap_or_default())
    };
    let (action, ip) = if let Some(ip) = first("Found") {
        (Some("Found"), Some(ip))
    } else if let Some(ip) = first("Restore Ban") {
        (Some("Restore Ban"), Some(ip))
    } else if let Some(ip) = first("Ban") {
        (Some("Ban"), Some(ip))
    } else if let Some(ip) = first("Unban") {
        (Some("Unban"), Some(ip))
    } else if let Some(ip) = first("Ignore") {
        (Some("Ignore"), Some(ip))
    } else if let Some(ip) = action_text.strip_suffix(" already banned") {
        (Some("already banned"), Some(ip))
    } else {
        (None, None)
    };
    Some(Fail2ban { time: Some(time), component, pid, level, jail, action, ip, message: body })
}

fn parse_fail2ban(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut seen = false;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if text.trim().is_empty() {
            return Ok(());
        }
        let record = match fail2ban_entry(input, text) {
            Some(record) => record,
            None if !seen => return Err(Error::format("not a fail2ban log: the first line starts no entry")),
            // A traceback or a wrapped message continues the entry before it.
            None => Fail2ban {
                time: None,
                component: "",
                pid: None,
                level: "",
                jail: None,
                action: None,
                ip: None,
                message: text,
            },
        };
        seen = true;
        sink.emit(Loc::Line(line.number), &record)
    })?;
    if seen {
        Ok(())
    } else {
        Err(Error::skipped("empty file"))
    }
}

// ---- DHCP leases ----

/// `3 2026/11/13 01:18:12` (weekday, date, time), or `epoch 1794533892`, as UTC.
fn lease_time(text: &str) -> Option<Timestamp> {
    let text = text.trim();
    if let Some(epoch) = text.strip_prefix("epoch ") {
        let secs = parse_uint(epoch.split([';', ' ']).next()?.as_bytes())?;
        return Timestamp::checked(i64::try_from(secs).ok()?, 0, Precision::Seconds, Basis::Recorded);
    }
    let mut words = text.split_ascii_whitespace();
    let mut date = words.next()?;
    if date.len() == 1 {
        date = words.next()?;
    }
    let time = words.next()?;
    let num = |s: &str| parse_uint(s.as_bytes()).and_then(|v| u32::try_from(v).ok());
    let mut d = date.split('/');
    let mut t = time.split(':');
    let secs = secs_from_civil(
        i64::from(num(d.next()?)?),
        num(d.next()?)?,
        num(d.next()?)?,
        num(t.next()?)?,
        num(t.next()?)?,
        num(t.next()?)?,
    )?;
    Some(Timestamp::from_secs(secs, Basis::Recorded))
}

fn unquote(text: &str) -> &str {
    text.trim().trim_end_matches(';').trim().trim_matches('"')
}

/// Statements of a block: `key rest;` with the trailing semicolon removed.
fn statement(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    let line = line.strip_suffix(';').unwrap_or(line);
    let (key, rest) = line.split_once(' ').unwrap_or((line, ""));
    (!key.is_empty() && !key.starts_with('#')).then_some((key, rest.trim()))
}

/// The most statements read in one block; a block that never closes cannot run away.
const MAX_BLOCK_LINES: usize = 500;

#[derive(Serialize)]
struct DhcpdLease {
    time: Option<Timestamp>,
    ip: String,
    starts: Option<Timestamp>,
    ends: Option<Timestamp>,
    /// Client last transaction time.
    cltt: Option<Timestamp>,
    binding_state: Option<String>,
    next_binding_state: Option<String>,
    mac: Option<String>,
    client_hostname: Option<String>,
    vendor_class: Option<String>,
}

impl Record for DhcpdLease {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "{} leased to {} {} ({})",
            self.ip,
            self.mac.as_deref().unwrap_or("?"),
            self.client_hostname.as_deref().unwrap_or(""),
            self.binding_state.as_deref().unwrap_or("?")
        );
        self.time.map(|t| Event::new(t, "dhcp_lease", message)).into_iter()
    }
}

fn parse_dhcpd(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut open: Option<(u64, DhcpdLease, usize)> = None;
    let mut leases = 0u64;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            return Ok(());
        }
        if let Some((start, lease, count)) = open.as_mut() {
            if text.starts_with('}') {
                let (start, lease) = (*start, std::mem::replace(lease, empty_lease()));
                open = None;
                leases += 1;
                return sink.emit(Loc::Line(start), &lease);
            }
            *count += 1;
            if *count > MAX_BLOCK_LINES {
                sink.warn(format!("line {start}: lease block longer than {MAX_BLOCK_LINES} statements, skipped"));
                open = None;
                return Ok(());
            }
            let Some((key, rest)) = statement(text) else { return Ok(()) };
            match key {
                "starts" => {
                    lease.starts = lease_time(rest);
                    lease.time = lease.starts;
                }
                "ends" => lease.ends = lease_time(rest),
                "cltt" => lease.cltt = lease_time(rest),
                "binding" => lease.binding_state = rest.strip_prefix("state ").map(|s| s.to_string()),
                "next" => lease.next_binding_state = rest.strip_prefix("binding state ").map(|s| s.to_string()),
                "hardware" => lease.mac = rest.strip_prefix("ethernet ").map(|s| s.to_string()),
                "client-hostname" => lease.client_hostname = Some(unquote(rest).to_string()),
                "set" => {
                    if let Some(value) = rest.strip_prefix("vendor-class-identifier") {
                        lease.vendor_class = Some(unquote(value.trim_start().trim_start_matches('=')).to_string());
                    }
                }
                _ => {}
            }
            return Ok(());
        }
        if let Some(rest) = text.strip_prefix("lease ") {
            if let Some(ip) = rest.strip_suffix('{').map(str::trim) {
                let mut lease = empty_lease();
                lease.ip = ip.to_string();
                open = Some((line.number, lease, 0));
            }
        }
        // `server-duid`, `authoring-byte-order` and the like are file headers.
        Ok(())
    })?;
    if let Some((start, ..)) = open {
        sink.warn(format!("line {start}: the lease block is not closed (the file ends inside it)"));
    }
    if leases == 0 && open.is_none() {
        return Err(Error::skipped("no leases"));
    }
    Ok(())
}

fn empty_lease() -> DhcpdLease {
    DhcpdLease {
        time: None,
        ip: String::new(),
        starts: None,
        ends: None,
        cltt: None,
        binding_state: None,
        next_binding_state: None,
        mac: None,
        client_hostname: None,
        vendor_class: None,
    }
}

#[derive(Serialize)]
struct ClientLease {
    /// When the lease was granted: `expire` minus the lease time. Derived, not logged.
    leased_at: Option<Timestamp>,
    interface: Option<String>,
    address: Option<String>,
    subnet_mask: Option<String>,
    routers: Option<String>,
    dns_servers: Option<String>,
    domain_name: Option<String>,
    dhcp_server: Option<String>,
    lease_seconds: Option<u64>,
    renew: Option<Timestamp>,
    rebind: Option<Timestamp>,
    expire: Option<Timestamp>,
}

impl Record for ClientLease {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "{} leased {} from {}",
            self.interface.as_deref().unwrap_or("?"),
            self.address.as_deref().unwrap_or("?"),
            self.dhcp_server.as_deref().unwrap_or("?")
        );
        self.leased_at.map(|t| Event::new(t, "dhcp_lease", message)).into_iter()
    }
}

fn parse_dhclient(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut open: Option<(u64, ClientLease, usize)> = None;
    let mut leases = 0u64;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            return Ok(());
        }
        let Some((start, lease, count)) = open.as_mut() else {
            if text.starts_with("lease") && text.ends_with('{') {
                open = Some((line.number, blank_client(), 0));
            }
            return Ok(());
        };
        if text.starts_with('}') {
            let (start, mut lease) = (*start, std::mem::replace(lease, blank_client()));
            open = None;
            leases += 1;
            lease.leased_at = lease.expire.zip(lease.lease_seconds).and_then(|(expire, secs)| {
                Timestamp::checked(
                    expire.utc / 1_000_000_000 - i64::try_from(secs).ok()?,
                    0,
                    Precision::Seconds,
                    Basis::Recorded,
                )
            });
            return sink.emit(Loc::Line(start), &lease);
        }
        *count += 1;
        if *count > MAX_BLOCK_LINES {
            sink.warn(format!("line {start}: lease block longer than {MAX_BLOCK_LINES} statements, skipped"));
            open = None;
            return Ok(());
        }
        let Some((key, rest)) = statement(text) else { return Ok(()) };
        match key {
            "interface" => lease.interface = Some(unquote(rest).to_string()),
            "fixed-address" => lease.address = Some(rest.to_string()),
            "renew" => lease.renew = lease_time(rest),
            "rebind" => lease.rebind = lease_time(rest),
            "expire" => lease.expire = lease_time(rest),
            "option" => {
                let (name, value) = rest.split_once(' ').unwrap_or((rest, ""));
                let value = Some(unquote(value).to_string());
                match name {
                    "subnet-mask" => lease.subnet_mask = value,
                    "routers" => lease.routers = value,
                    "domain-name-servers" => lease.dns_servers = value,
                    "domain-name" => lease.domain_name = value,
                    "dhcp-server-identifier" => lease.dhcp_server = value,
                    "dhcp-lease-time" => lease.lease_seconds = value.and_then(|v| v.parse().ok()),
                    _ => {}
                }
            }
            _ => {}
        }
        Ok(())
    })?;
    if let Some((start, ..)) = open {
        sink.warn(format!("line {start}: the lease block is not closed (the file ends inside it)"));
    }
    if leases == 0 && open.is_none() {
        return Err(Error::skipped("no leases"));
    }
    Ok(())
}

fn blank_client() -> ClientLease {
    ClientLease {
        leased_at: None,
        interface: None,
        address: None,
        subnet_mask: None,
        routers: None,
        dns_servers: None,
        domain_name: None,
        dhcp_server: None,
        lease_seconds: None,
        renew: None,
        rebind: None,
        expire: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    fn records(out: &str) -> Vec<&str> {
        out.lines().take_while(|l| !l.starts_with("---")).collect()
    }

    fn clean(out: &str) {
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
    }

    /// Fixture: real BIND 9.18 query log, 8 `dig` queries (A, AAAA, MX, TXT over TCP, NXDOMAIN, PTR,
    /// no-recursion, ANY).
    #[test]
    fn named_queries_match_dig() {
        let out = run(&NAMED, "var/log/named/query.log", &fixture("svclogs/named/query.log"), 0);
        clean(&out);
        assert_eq!(records(&out).len(), 8);
        for (qtype, flags) in [
            ("A", "+E(0)K"),
            ("AAAA", "+E(0)K"),
            ("MX", "+E(0)K"),
            ("TXT", "+E(0)TK"),
            ("PTR", "+E(0)K"),
            ("A", "-E(0)"),
            ("ANY", "+E(0)TK"),
        ] {
            assert!(out.contains(&format!("\"qtype\":\"{qtype}\",\"flags\":\"{flags}\"")), "{qtype} {flags}");
        }
        assert!(
            out.contains("\"time\":\"2026-11-13T01:24:56.747Z\"") && out.contains("\"client_port\":35571"),
            "{out}"
        );
        assert!(out.contains("\"qname\":\"nosuch.example.test\""), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn named_other_categories_are_not_records_and_garbage_is_one_warning() {
        let data = b"13-Nov-2026 01:16:32.281 general: info: running\n13-Nov-2026 01:16:32.281 queries: info: client 1.2.3.4#5 (a.b): query: a.b IN A +\nnot a time\nnot a time either\n";
        let out = run(&NAMED, "var/log/named/query.log", data, 0);
        assert_eq!(records(&out).len(), 1, "{out}");
        assert_eq!(out.matches("--- warning").count(), 1, "{out}");
    }

    /// Fixture: real fail2ban 1.0.2 with the sshd jail (maxretry 3), real sshd failures, `unbanip`.
    #[test]
    fn fail2ban_actions_match_the_jail() {
        let data = fixture("svclogs/fail2ban/fail2ban.log");
        let out = run(&FAIL2BAN, "var/log/fail2ban.log", &data, 0);
        clean(&out);
        let text = String::from_utf8_lossy(&data);
        let count = |needle: &str| text.lines().filter(|l| l.contains(needle)).count();
        assert_eq!(records(&out).len(), text.lines().count());
        for (action, needle) in
            [("Found", "] Found "), ("Ban", "] Ban "), ("Unban", "] Unban "), ("already banned", " already banned")]
        {
            assert_eq!(out.matches(&format!("\"action\":\"{action}\"")).count(), count(needle), "{action}");
        }
        assert!(out.contains("\"jail\":\"sshd\",\"action\":\"Ban\",\"ip\":\"127.0.0.1\""), "{out}");
        assert!(out.contains("f2b_ban") && out.contains("f2b_unban") && out.contains("f2b_found"));
        insta::assert_snapshot!(out);
    }

    #[test]
    fn fail2ban_old_format_and_continuations() {
        let data = b"2014-03-10 01:02:03,123 fail2ban.actions: WARNING [ssh] Ban 192.0.2.1\nTraceback (most recent call last):\n  File x\n";
        let out = run(&FAIL2BAN, "var/log/fail2ban.log", data, 0);
        assert!(out.contains("\"pid\":null,\"level\":\"WARNING\",\"jail\":\"ssh\",\"action\":\"Ban\""), "{out}");
        assert_eq!(out.matches("\"time\":null").count(), 2, "{out}");
        assert!(run(&FAIL2BAN, "var/log/fail2ban.log", b"hello\n", 0).contains("not a fail2ban log"));
    }

    /// Fixture: real isc-dhcp-server 4.4.3 answering real dhclient 4.4.3 on a Docker network.
    #[test]
    fn dhcp_server_and_client_leases() {
        let server = run(&DHCPD_LEASES, "var/lib/dhcp/dhcpd.leases", &fixture("svclogs/dhcp/dhcpd.leases"), 0);
        clean(&server);
        assert_eq!(records(&server).len(), 1);
        assert!(
            server.contains(
                "\"ip\":\"10.77.0.100\",\"starts\":\"2026-11-13T01:28:38Z\",\"ends\":\"2026-11-13T01:38:38Z\""
            ),
            "{server}"
        );
        assert!(
            server.contains("\"mac\":\"02:42:0a:4d:00:aa\"") && server.contains("\"binding_state\":\"active\""),
            "{server}"
        );
        let client = run(&DHCLIENT_LEASES, "var/lib/dhcp/dhclient.leases", &fixture("svclogs/dhcp/dhclient.leases"), 0);
        clean(&client);
        assert_eq!(records(&client).len(), 1);
        assert!(
            client.contains("\"leased_at\":\"2026-11-13T01:28:38Z\"") && client.contains("\"address\":\"10.77.0.100\""),
            "{client}"
        );
        assert!(client.contains("\"dhcp_server\":\"10.77.0.2\",\"lease_seconds\":600"), "{client}");
        insta::assert_snapshot!(format!("{server}{client}"));
    }

    #[test]
    fn unclosed_blocks_and_hostile_text_are_reported_not_trusted() {
        let out =
            run(&DHCPD_LEASES, "var/lib/dhcp/dhcpd.leases", b"lease 10.0.0.1 {\n  starts 5 2026/11/13 01:28:38;\n", 0);
        assert!(out.contains("not closed"), "{out}");
        let mut long = b"lease 10.0.0.1 {\n".to_vec();
        for _ in 0..600 {
            long.extend_from_slice(b"  uid x;\n");
        }
        assert!(run(&DHCPD_LEASES, "var/lib/dhcp/dhcpd.leases", &long, 0).contains("longer than"));
        assert!(run(&DHCPD_LEASES, "var/lib/dhcp/dhcpd.leases", b"nothing here\n", 0).contains("skipped"));
    }

    #[test]
    fn hostile_input_never_panics() {
        let mut seed = 99u64;
        for (artifact, name) in [
            (&NAMED, "svclogs/named/query.log"),
            (&FAIL2BAN, "svclogs/fail2ban/fail2ban.log"),
            (&DHCPD_LEASES, "svclogs/dhcp/dhcpd.leases"),
            (&DHCLIENT_LEASES, "svclogs/dhcp/dhclient.leases"),
        ] {
            let full = fixture(name);
            for cut in (0..full.len()).step_by(3) {
                run(artifact, "var/log/x", &full[..cut], 0);
            }
            for _ in 0..600 {
                let mut copy = full.clone();
                for _ in 0..4 {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let at = (seed >> 33) as usize % copy.len();
                    copy[at] = (seed >> 20) as u8;
                }
                run(artifact, "var/log/x", &copy, 0);
            }
        }
    }
}
