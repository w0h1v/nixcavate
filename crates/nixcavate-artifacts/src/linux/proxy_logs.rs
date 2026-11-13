//! Logs of proxies and load balancers, as files:
//!
//! - HAProxy: the HTTP (`option httplog`) and TCP (`option tcplog`) lines as syslog carries them
//!   into `haproxy.log`. Format: HAProxy configuration manual, "Logging" (default log formats).
//! - Squid `access.log` in the native format (`logformat squid`: epoch.millis, elapsed, client,
//!   code/status, bytes, method, URL, user, hierarchy/peer, type) and the `combined` format;
//!   Squid documentation, `logformat`.
//! - Squid `cache.log`: `2024/03/10 01:02:03 kid1| message`.
//!
//! HAProxy's `accept_date` carries no zone, so it is the host zone assumed; the syslog time of
//! the line, which does, is kept as `logged`. A Squid time is the end of the transaction.

use crate::common::logfmt::{clf_utc, clf_wall, cut, Unparsed};
use crate::common::stamped_log::{parse as stamped, Parsed};
use crate::common::syslog::parse_header;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, UNIX};
use nixcavate_core::time::{parse_uint, secs_from_civil};
use nixcavate_core::{Basis, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::fmt::Write as _;

pub const HAPROXY: Artifact = Artifact::new(
    "haproxy-log",
    "HAProxy HTTP and TCP request logs",
    Category::Logs,
    UNIX,
    &["var/log/haproxy.log*", "var/log/haproxy/*.log*", "var/log/haproxy/haproxy*"],
    parse_haproxy,
)
.split_lines();

pub const SQUID_ACCESS: Artifact = Artifact::new(
    "squid-access-log",
    "Squid proxy access logs (native and combined formats)",
    Category::Logs,
    UNIX,
    &[
        "var/log/squid/access.log*",
        "var/log/squid3/access.log*",
        "var/log/squid/combined.log*",
        "var/log/squid/*access*",
    ],
    parse_squid_access,
)
.split_lines();

pub const SQUID_CACHE: Artifact = Artifact::new(
    "squid-cache-log",
    "Squid cache.log: start, stop and errors",
    Category::Logs,
    UNIX,
    &["var/log/squid/cache.log*", "var/log/squid3/cache.log*"],
    |input, sink| stamped(input, sink, "a Squid cache.log", "squid", squid_cache_line),
);

// ---- HAProxy ----

#[derive(Serialize)]
struct Haproxy<'a> {
    time: Option<Timestamp>,
    /// When syslog logged the line (the end of the request).
    logged: Option<Timestamp>,
    log_host: &'a str,
    /// `http` or `tcp`.
    mode: &'static str,
    client_ip: &'a str,
    client_port: Option<u32>,
    frontend: &'a str,
    backend: &'a str,
    server: &'a str,
    /// Milliseconds: request wait, queue, connect, server response, total. -1 in the log (the
    /// phase never happened) is empty here.
    t_request: Option<i64>,
    t_queue: Option<i64>,
    t_connect: Option<i64>,
    t_response: Option<i64>,
    t_total: Option<i64>,
    status: Option<u16>,
    bytes: Option<u64>,
    /// The four-letter termination state (`----` is a normal end, `SC--` a connect failure).
    termination_state: &'a str,
    method: &'a str,
    request: &'a str,
}

impl Record for Haproxy<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let mut message = format!("{} -> {}/{}/{}", self.client_ip, self.frontend, self.backend, self.server);
        if !self.request.is_empty() {
            let _ = write!(message, " {} {}", self.method, cut(self.request));
        }
        if let Some(status) = self.status {
            let _ = write!(message, " -> {status}");
        }
        self.time.or(self.logged).map(|t| Event::new(t, "proxy_request", message)).into_iter()
    }
}

fn int(token: &str) -> Option<i64> {
    token.parse().ok().filter(|v| *v >= 0)
}

fn parse_haproxy(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut unparsed = Unparsed::default();
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let header = parse_header(input, text.trim_end().as_bytes());
        if !header.program.starts_with("haproxy") {
            return Ok(());
        }
        match haproxy_message(input, &header.message) {
            Some(mut record) => {
                record.logged = header.time;
                record.log_host = &header.log_host;
                sink.emit(Loc::Offset(line.offset), &record)
            }
            // Start-up, health-check and `Proxy x started` lines are not requests.
            None if !header.message.starts_with(|c: char| c.is_ascii_digit() || c == ':') => Ok(()),
            None => {
                unparsed.note(line.number);
                Ok(())
            }
        }
    })?;
    unparsed.report(sink, "HAProxy http or tcp log");
    Ok(())
}

fn haproxy_message<'a>(input: &Input, message: &'a str) -> Option<Haproxy<'a>> {
    let (client, rest) = message.split_once(' ')?;
    let (client_ip, port) = client.rsplit_once(':')?;
    let rest = rest.strip_prefix('[')?;
    let (date, rest) = rest.split_once("] ")?;
    let (wall, used) = clf_wall(date.as_bytes())?;
    let (nanos, precision) = match date.get(used..)?.strip_prefix('.') {
        Some(ms) => (u32::try_from(parse_uint(ms.as_bytes())?).ok()?.checked_mul(1_000_000)?, Precision::Millis),
        None => (0, Precision::Seconds),
    };
    let time = input.local_time(wall, nanos, precision);
    let (frontend, rest) = rest.split_once(' ')?;
    let (backend_server, rest) = rest.split_once(' ')?;
    let (backend, server) = backend_server.split_once('/').unwrap_or((backend_server, ""));
    let (timers, rest) = rest.split_once(' ')?;
    let timer: Vec<Option<i64>> = timers.split('/').map(|t| int(t.trim_start_matches('+'))).collect();
    let mut record = Haproxy {
        time: Some(time),
        logged: None,
        log_host: "",
        mode: "tcp",
        client_ip,
        client_port: port.parse().ok(),
        frontend,
        backend,
        server,
        t_request: None,
        t_queue: None,
        t_connect: None,
        t_response: None,
        t_total: None,
        status: None,
        bytes: None,
        termination_state: "",
        method: "",
        request: "",
    };
    match timer.len() {
        5 => {
            record.mode = "http";
            [record.t_request, record.t_queue, record.t_connect, record.t_response, record.t_total] =
                [timer[0], timer[1], timer[2], timer[3], timer[4]];
            let (status, rest) = rest.split_once(' ')?;
            let (bytes, rest) = rest.split_once(' ')?;
            // Captured request and response cookies, then the termination state and counters.
            let mut words = rest.splitn(4, ' ');
            let (_, _, state) = (words.next()?, words.next()?, words.next()?);
            let tail = words.next()?;
            record.status = status.parse().ok();
            record.bytes = bytes.trim_start_matches('+').parse().ok();
            record.termination_state = state;
            // The request is the last quoted field; captured headers in braces come before it.
            let quote = tail.find('"')?;
            let request = tail.get(quote + 1..)?.strip_suffix('"')?;
            record.request = request;
            record.method = request.split(' ').next().unwrap_or_default();
        }
        3 => {
            [record.t_queue, record.t_connect, record.t_total] = [timer[0], timer[1], timer[2]];
            let (bytes, rest) = rest.split_once(' ')?;
            let (state, _) = rest.split_once(' ')?;
            record.bytes = bytes.trim_start_matches('+').parse().ok();
            record.termination_state = state;
        }
        _ => return None,
    }
    Some(record)
}

// ---- Squid access.log ----

#[derive(Serialize)]
struct SquidAccessRecord<'a> {
    time: Option<Timestamp>,
    /// `native` or `combined`.
    format: &'static str,
    elapsed_ms: Option<u64>,
    client: &'a str,
    /// Squid's result code (`TCP_MISS`, `TCP_DENIED`, `TCP_TUNNEL`).
    result: &'a str,
    status: Option<u16>,
    bytes: Option<u64>,
    method: &'a str,
    url: &'a str,
    user: &'a str,
    /// `HIER_DIRECT`, `HIER_NONE`, a parent cache code.
    hierarchy: &'a str,
    peer: &'a str,
    mime: Option<&'a str>,
    referer: Option<&'a str>,
    user_agent: Option<&'a str>,
}

impl Record for SquidAccessRecord<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let mut message = format!("{} {} {}", self.client, self.method, cut(self.url));
        let _ = write!(message, " -> {} {}", self.result, self.status.unwrap_or(0));
        self.time.map(|t| Event::new(t, "proxy_request", message)).into_iter()
    }
}

fn parse_squid_access(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut unparsed = Unparsed::default();
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if text.is_empty() {
            return Ok(());
        }
        match squid_native(text).or_else(|| squid_combined(text)) {
            Some(record) => sink.emit(Loc::Offset(line.offset), &record),
            None => {
                unparsed.note(line.number);
                Ok(())
            }
        }
    })?;
    unparsed.report(sink, "Squid native or combined access log");
    Ok(())
}

fn code_status(token: &str) -> (&str, Option<u16>) {
    match token.rsplit_once('/') {
        Some((code, status)) => (code, status.parse().ok()),
        None => (token, None),
    }
}

/// `1794532608.451 1 127.0.0.1 TCP_MISS/200 327 GET http://x/ - HIER_DIRECT/127.0.0.1 text/html`
fn squid_native(text: &str) -> Option<SquidAccessRecord<'_>> {
    let mut words = text.split_ascii_whitespace();
    let stamp = words.next()?;
    let (secs, millis) = stamp.split_once('.')?;
    if millis.len() != 3 {
        return None;
    }
    let (secs, millis) = (parse_uint(secs.as_bytes())?, parse_uint(millis.as_bytes())?);
    let elapsed = words.next()?;
    let client = words.next()?;
    let (result, status) = code_status(words.next()?);
    let bytes = words.next()?;
    let (method, url, user, hier) = (words.next()?, words.next()?, words.next()?, words.next()?);
    let mime = words.next();
    let (hierarchy, peer) = hier.split_once('/').unwrap_or((hier, ""));
    Some(SquidAccessRecord {
        time: Timestamp::checked(
            i64::try_from(secs).ok()?,
            u32::try_from(millis).ok()? * 1_000_000,
            Precision::Millis,
            Basis::Recorded,
        ),
        format: "native",
        elapsed_ms: elapsed.parse().ok(),
        client,
        result,
        status,
        bytes: bytes.parse().ok(),
        method,
        url,
        user,
        hierarchy,
        peer,
        mime: mime.filter(|m| *m != "-"),
        referer: None,
        user_agent: None,
    })
}

/// `127.0.0.1 - - [10/Mar/2024:01:02:03 +0000] "GET http://x/ HTTP/1.1" 200 327 "-" "ua" TCP_MISS:HIER_DIRECT`
fn squid_combined(text: &str) -> Option<SquidAccessRecord<'_>> {
    let (client, rest) = text.split_once(' ')?;
    let (_ident, rest) = rest.split_once(' ')?;
    let (user, rest) = rest.split_once(" [")?;
    let (date, rest) = rest.split_once("] \"")?;
    let (request, rest) = rest.split_once("\" ")?;
    let (status, rest) = rest.split_once(' ')?;
    let (bytes, rest) = rest.split_once(' ')?;
    let rest = rest.strip_prefix('"')?;
    let (referer, rest) = rest.split_once("\" \"")?;
    let (agent, tail) = rest.split_once('"')?;
    let (method, url) = request.split_once(' ').map(|(m, r)| (m, r.rsplit_once(' ').map_or(r, |(u, _)| u)))?;
    let (result, hierarchy) = tail.trim().split_once(':').unwrap_or((tail.trim(), ""));
    Some(SquidAccessRecord {
        time: clf_utc(date.as_bytes()).map(|s| Timestamp::from_secs(s, Basis::Recorded)),
        format: "combined",
        elapsed_ms: None,
        client,
        result,
        status: status.parse().ok(),
        bytes: bytes.parse().ok(),
        method,
        url,
        user,
        hierarchy,
        peer: "",
        mime: None,
        referer: Some(referer),
        user_agent: Some(agent),
    })
}

// ---- Squid cache.log ----

/// `2024/03/10 01:02:03 kid1| message`, or `2024/03/10 01:02:03| message` before Squid 3.2.
fn squid_cache_line<'a>(input: &Input, line: &'a str) -> Option<Parsed<'a>> {
    let b = line.as_bytes();
    let num = |from: usize, len: usize| parse_uint(b.get(from..from + len)?).and_then(|v| u32::try_from(v).ok());
    if b.get(4) != Some(&b'/')
        || b.get(7) != Some(&b'/')
        || b.get(10) != Some(&b' ')
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
    {
        return None;
    }
    let wall = secs_from_civil(i64::from(num(0, 4)?), num(5, 2)?, num(8, 2)?, num(11, 2)?, num(14, 2)?, num(17, 2)?)?;
    let rest = line.get(19..)?;
    let (source, message) = match rest.strip_prefix('|') {
        Some(message) => (None, message),
        None => {
            let (source, message) = rest.trim_start().split_once('|')?;
            (Some(source).filter(|s| !s.contains(' ')), message)
        }
    };
    let message = message.trim_start();
    let level = ["ERROR", "WARNING", "FATAL", "SECURITY ALERT", "ALERT"]
        .into_iter()
        .find(|l| message.starts_with(&format!("{l}:")));
    Some(Parsed {
        time: Some(input.local_time(wall, 0, Precision::Seconds)),
        level,
        source,
        pid: None,
        message,
        timeline: true,
    })
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

    /// Fixture: real HAProxy 2.6 through rsyslog, driven by curl: 10 requests (7 on the HTTP frontend
    /// with 2 servers, 1 answered 503 by a dead backend after the connect timer, 2 on the TCP frontend).
    #[test]
    fn haproxy_http_and_tcp_lines() {
        let data = fixture("svclogs/haproxy/haproxy.log");
        let out = run(&HAPROXY, "var/log/haproxy.log", &data, 0);
        clean(&out);
        assert_eq!(records(&out).len(), 10);
        let dead = records(&out).into_iter().find(|l| l.contains("\"backend\":\"dead\"")).unwrap_or_default();
        assert!(
            dead.contains("\"status\":503")
                && dead.contains("\"termination_state\":\"SC--\"")
                && dead.contains("\"t_total\":3007"),
            "{dead}"
        );
        assert!(dead.contains("\"t_connect\":null") && dead.contains("\"mode\":\"http\""), "{dead}");
        let tcp = records(&out).into_iter().filter(|l| l.contains("\"mode\":\"tcp\"")).count();
        assert_eq!(tcp, 2);
        assert!(out.contains("\"method\":\"POST\",\"request\":\"POST /login HTTP/1.1\""), "{out}");
        assert!(
            out.contains("\"time\":\"2026-11-13T01:22:06.047Z\"")
                && out.contains("\"logged\":\"2026-11-13T01:22:06Z\""),
            "{out}"
        );
        insta::assert_snapshot!(out);
    }

    /// Fixture: real Squid 5.7 with the native and the combined log of the same 7 requests.
    #[test]
    fn squid_native_and_combined_describe_the_same_requests() {
        let native = run(&SQUID_ACCESS, "var/log/squid/access.log", &fixture("svclogs/squid/access.log"), 0);
        let combined = run(&SQUID_ACCESS, "var/log/squid/combined.log", &fixture("svclogs/squid/combined.log"), 0);
        clean(&native);
        clean(&combined);
        assert_eq!((records(&native).len(), records(&combined).len()), (7, 7));
        for key in ["\"result\":\"TCP_DENIED\"", "\"status\":404", "\"result\":\"TCP_MEM_HIT\"", "\"status\":503"] {
            assert!(native.contains(key) && combined.contains(key), "{key}");
        }
        assert!(
            native.contains("\"elapsed_ms\":60129") && native.contains("\"time\":\"2026-11-13T01:23:16.261Z\""),
            "{native}"
        );
        assert!(
            combined.contains("\"user_agent\":\"scanner/2 (x)\"")
                && combined.contains("\"time\":\"2026-11-13T01:23:16Z\""),
            "{combined}"
        );
        insta::assert_snapshot!(native);
    }

    #[test]
    fn squid_cache_log_is_read_as_entries() {
        let data = fixture("svclogs/squid/cache.log");
        let out = run(&SQUID_CACHE, "var/log/squid/cache.log", &data, 0);
        clean(&out);
        assert_eq!(records(&out).len(), data.split(|b| *b == b'\n').filter(|l| !l.is_empty()).count());
        assert!(out.contains("Starting Squid Cache version 5.7"), "{out}");
    }

    #[test]
    fn unknown_lines_make_one_warning_and_other_files_are_refused() {
        let out = run(&HAPROXY, "var/log/haproxy.log", b"2024-03-10T01:02:03+00:00 h haproxy[1]: 1.2.3.4:5 [x] bad\n2024-03-10T01:02:03+00:00 h haproxy[1]: Proxy web started.\n", 0);
        assert_eq!(out.matches("--- warning").count(), 1, "{out}");
        assert!(
            run(&SQUID_ACCESS, "var/log/squid/access.log", b"nonsense\n", 0).contains("1 lines are not in the Squid")
        );
        assert!(run(&SQUID_CACHE, "var/log/squid/cache.log", b"nonsense\n", 0).contains("not a Squid cache.log"));
    }

    #[test]
    fn hostile_lines_never_panic() {
        let mut seed = 0x1234_5678_9abc_def1u64;
        for (artifact, path, name) in [
            (&HAPROXY, "var/log/haproxy.log", "svclogs/haproxy/haproxy.log"),
            (&SQUID_ACCESS, "var/log/squid/access.log", "svclogs/squid/access.log"),
            (&SQUID_ACCESS, "var/log/squid/access.log", "svclogs/squid/combined.log"),
            (&SQUID_CACHE, "var/log/squid/cache.log", "svclogs/squid/cache.log"),
        ] {
            let full = fixture(name);
            for cut in (0..full.len()).step_by(11) {
                run(artifact, path, &full[..cut], 0);
            }
            for _ in 0..800 {
                let mut copy = full.clone();
                for _ in 0..4 {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let at = (seed >> 33) as usize % copy.len();
                    copy[at] = (seed >> 20) as u8;
                }
                run(artifact, path, &copy, 0);
            }
        }
    }
}
