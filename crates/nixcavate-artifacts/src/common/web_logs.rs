//! Apache and nginx web server logs.
//!
//! Access logs: Apache mod_log_config (Common Log Format and the Combined format, plus the
//! Debian `vhost_combined` variant that starts with `%v:%p`) and nginx ngx_http_log_module's
//! `combined`. Error logs: Apache 2.4 default `ErrorLogFormat` (2.2 style lines parse too) and
//! the nginx error log.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, ANY_OS};
use memchr::{memchr, memchr2};
use nixcavate_core::time::{month_from_abbrev, parse_uint, secs_from_civil};
use nixcavate_core::{Basis, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::fmt::Write as _;

pub const ACCESS: Artifact = Artifact::new(
    "web-access-log",
    "Apache and nginx access logs",
    Category::Logs,
    ANY_OS,
    &[
        "var/log/apache2/*access*",
        "var/log/httpd/*access*",
        "var/log/nginx/*access*",
        "private/var/log/apache2/*access*",
        "usr/local/var/log/nginx/*access*",
    ],
    parse_access,
)
.split_lines();

pub const ERROR: Artifact = Artifact::new(
    "web-error-log",
    "Apache and nginx error logs",
    Category::Logs,
    ANY_OS,
    &[
        "var/log/apache2/*error*",
        "var/log/httpd/*error*",
        "var/log/nginx/*error*",
        "private/var/log/apache2/*error*",
        "usr/local/var/log/nginx/*error*",
    ],
    parse_error,
)
.split_lines();

/// The longest request shown in a timeline message.
const MESSAGE_CAP: usize = 200;

fn capped(text: &str) -> &str {
    let mut end = MESSAGE_CAP.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// `text[start..end]`, or empty if the range is not valid (never panics on hostile input).
fn slice(text: &str, start: usize, end: usize) -> &str {
    text.get(start..end).unwrap_or("")
}

fn two(b: &[u8], i: usize) -> Option<u32> {
    let (hi, lo) = (*b.get(i)?, *b.get(i + 1)?);
    (hi.is_ascii_digit() && lo.is_ascii_digit()).then(|| u32::from(hi - b'0') * 10 + u32::from(lo - b'0'))
}

fn four(b: &[u8], i: usize) -> Option<i64> {
    Some(i64::from(two(b, i)? * 100 + two(b, i + 2)?))
}

/// Finds the closing quote of the quoted field whose opening quote is at `open`. Both Apache
/// (`\"`) and nginx (`\x22`) escape quotes, so a backslash always protects the next byte.
fn closing_quote(b: &[u8], open: usize) -> Option<usize> {
    let mut i = open + 1;
    while let Some(found) = memchr2(b'"', b'\\', b.get(i..)?) {
        i += found;
        if b[i] == b'"' {
            return Some(i);
        }
        i += 2;
    }
    None
}

/// Reports lines that matched no known format once per chunk: a warning per line would be
/// too costly on logs with millions of probes.
#[derive(Default)]
struct Unparsed {
    count: u64,
    first: u64,
}

impl Unparsed {
    fn note(&mut self, offset: u64) {
        if self.count == 0 {
            self.first = offset;
        }
        self.count += 1;
    }

    fn report(&self, sink: &mut Sink) {
        if self.count > 0 {
            sink.warn(format!(
                "{} lines were not in a known log format; the first is at offset {}",
                self.count, self.first
            ));
        }
    }
}

// ---- access log -------------------------------------------------------------------------

#[derive(Serialize)]
struct Access<'a> {
    time: Timestamp,
    vhost: Option<&'a str>,
    remote_address: &'a str,
    ident: &'a str,
    user: &'a str,
    method: &'a str,
    /// The request target, or the whole raw request line when it is not `METHOD target HTTP/x`.
    request: &'a str,
    protocol: &'a str,
    status: Option<u16>,
    bytes: Option<u64>,
    /// `None` in Common Log Format, where the field does not exist; a literal `-` is kept.
    referer: Option<&'a str>,
    user_agent: Option<&'a str>,
    /// Anything after the user agent (nginx `$http_x_forwarded_for`, custom fields).
    extra: &'a str,
}

impl Record for Access<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        // Built by hand: this runs for every line, and `format!` plus a status `String` cost
        // as much as parsing the line.
        let request = capped(self.request);
        let mut message = String::with_capacity(self.remote_address.len() + self.method.len() + request.len() + 12);
        message.push_str(self.remote_address);
        message.push(' ');
        if !self.method.is_empty() {
            message.push_str(self.method);
            message.push(' ');
        }
        message.push_str(request);
        message.push_str(" -> ");
        match self.status {
            Some(status) => {
                let _ = write!(message, "{status}");
            }
            None => message.push('-'),
        }
        Some(Event::new(self.time, "http_request", message)).into_iter()
    }
}

/// Index of the `[` of the first ` [` in `b`. A plain byte search beats building a substring
/// searcher for every line.
fn find_time_bracket(b: &[u8]) -> Option<usize> {
    let mut from = 0;
    loop {
        let at = from + memchr(b'[', b.get(from..)?)?;
        if at > 0 && b[at - 1] == b' ' {
            return Some(at);
        }
        from = at + 1;
    }
}

/// `10/Mar/2024:01:02:03 +0000` (26 bytes) as UTC seconds.
fn access_time(b: &[u8]) -> Option<i64> {
    let ok = b.len() == 26 && b[2] == b'/' && b[6] == b'/' && b[11] == b':' && b[14] == b':' && b[17] == b':';
    if !ok || !(b[20] == b' ' && (b[21] == b'+' || b[21] == b'-')) {
        return None;
    }
    let wall =
        secs_from_civil(four(b, 7)?, month_from_abbrev(&b[3..6])?, two(b, 0)?, two(b, 12)?, two(b, 15)?, two(b, 18)?)?;
    let zone = i64::from(two(b, 22)? * 3600 + two(b, 24)? * 60);
    Some(if b[21] == b'+' { wall - zone } else { wall + zone })
}

/// Splits a request line into method, target and protocol; `None` when it is anything else.
fn split_request(raw: &str) -> Option<(&str, &str, &str)> {
    let (method, rest) = raw.split_once(' ')?;
    let (target, protocol) = rest.rsplit_once(' ')?;
    let method_ok = !method.is_empty() && method.bytes().all(|c| c.is_ascii_uppercase());
    (method_ok && protocol.starts_with("HTTP/")).then_some((method, target, protocol))
}

fn parse_access_line(text: &str) -> Option<Access<'_>> {
    let b = text.as_bytes();
    let first_end = memchr(b' ', b)?;
    let second_end = first_end + 1 + memchr(b' ', &b[first_end + 1..])?;
    // `vhost:port ` prefix (Debian vhost_combined). An IPv6 address also contains colons, but
    // is followed by an ident, which is `-` in practice, while the vhost is followed by a host.
    let first = slice(text, 0, first_end);
    let digits_after_colon = first.rsplit_once(':').is_some_and(|(_, port)| parse_uint(port.as_bytes()).is_some());
    let vhost_layout = digits_after_colon && slice(text, first_end + 1, second_end) != "-";

    let (vhost, host_start) = if vhost_layout { (Some(first), first_end + 1) } else { (None, 0) };
    let host_end = if vhost_layout { second_end } else { first_end };
    let ident_start = host_end + 1;
    let ident_end = ident_start + memchr(b' ', b.get(ident_start..)?)?;
    // The user may contain spaces; the time stamp is the next ` [`.
    let user_start = ident_end + 1;
    let time_start = user_start + find_time_bracket(b.get(user_start..)?)? + 1;
    let user_end = time_start - 2;
    let time = Timestamp::from_secs(access_time(b.get(time_start..time_start + 26)?)?, Basis::Recorded);

    let quote = time_start + 28;
    if b.get(time_start + 26..quote + 1) != Some(b"] \"") {
        return None;
    }
    let close = closing_quote(b, quote)?;
    let raw_request = slice(text, quote + 1, close);
    let (method, request, protocol) = split_request(raw_request).unwrap_or(("", raw_request, ""));

    // Everything after the request is optional so that a truncated final line still counts.
    let mut pos = close + 1;
    let token = |pos: &mut usize| -> &str {
        if b.get(*pos) != Some(&b' ') {
            return "";
        }
        let start = *pos + 1;
        let end = memchr(b' ', &b[start..]).map_or(b.len(), |i| start + i);
        *pos = end;
        slice(text, start, end)
    };
    let status = parse_uint(token(&mut pos).as_bytes()).and_then(|v| u16::try_from(v).ok());
    let bytes = parse_uint(token(&mut pos).as_bytes());

    let quoted = |pos: &mut usize| -> Option<&str> {
        if b.get(*pos..*pos + 2) != Some(b" \"") {
            return None;
        }
        let end = closing_quote(b, *pos + 1)?;
        let value = slice(text, *pos + 2, end);
        *pos = end + 1;
        Some(value)
    };
    let referer = quoted(&mut pos);
    let user_agent = if referer.is_some() { quoted(&mut pos) } else { None };
    let extra = slice(text, pos, b.len()).trim_start();

    Some(Access {
        time,
        vhost,
        remote_address: slice(text, host_start, host_end),
        ident: slice(text, ident_start, ident_end),
        user: slice(text, user_start, user_end),
        method,
        request,
        protocol,
        status,
        bytes,
        referer,
        user_agent,
        extra,
    })
}

fn parse_access(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut unparsed = Unparsed::default();
    for_each_line(input, |line| {
        if line.bytes.is_empty() {
            return Ok(());
        }
        let text = lossy(line.bytes);
        match parse_access_line(&text) {
            Some(record) => sink.emit(Loc::Offset(line.offset), &record),
            None => {
                unparsed.note(line.offset);
                Ok(())
            }
        }
    })?;
    unparsed.report(sink);
    Ok(())
}

// ---- error log --------------------------------------------------------------------------

#[derive(Serialize)]
struct ErrorEntry<'a> {
    time: Option<Timestamp>,
    /// `apache` or `nginx`.
    server: &'static str,
    level: &'a str,
    /// Apache module (`core`, `ssl`...); nginx has none.
    module: Option<&'a str>,
    pid: Option<u32>,
    remote_address: Option<&'a str>,
    remote_port: Option<u16>,
    message: &'a str,
}

impl Record for ErrorEntry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("{} [{}] {}", self.server, self.level, capped(self.message));
        self.time.map(|ts| Event::new(ts, "http_error", message)).into_iter()
    }
}

/// `Sun Mar 10 01:02:03.123456 2024` (the fraction is absent in Apache 2.2).
fn apache_time(input: &Input, text: &str) -> Option<Timestamp> {
    let mut parts = text.split_ascii_whitespace();
    let (_weekday, month, day, clock, year) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let c = clock.as_bytes();
    if c.get(2) != Some(&b':') || c.get(5) != Some(&b':') {
        return None;
    }
    let wall = secs_from_civil(
        parse_uint(year.as_bytes())? as i64,
        month_from_abbrev(month.as_bytes())?,
        u32::try_from(parse_uint(day.as_bytes())?).ok()?,
        two(c, 0)?,
        two(c, 3)?,
        two(c, 6)?,
    )?;
    let Some(fraction) = c.get(9..) else { return Some(input.local_time(wall, 0, Precision::Seconds)) };
    // Scale the digits to nanoseconds: ".123456" is 123456000.
    let digits = fraction.get(..9.min(fraction.len()))?;
    let nanos = parse_uint(digits)? as u32 * 10u32.pow(9 - digits.len() as u32);
    Some(input.local_time(wall, nanos, Precision::Micros))
}

/// `[group]` starting at `pos`: its content and the position after it and the following space.
fn bracket(b: &[u8], pos: usize) -> Option<(usize, usize, usize)> {
    if b.get(pos) != Some(&b'[') {
        return None;
    }
    let close = pos + 1 + memchr(b']', &b[pos + 1..])?;
    let next = if b.get(close + 1) == Some(&b' ') { close + 2 } else { close + 1 };
    Some((pos + 1, close, next))
}

fn parse_apache_error<'a>(input: &Input, text: &'a str) -> Option<ErrorEntry<'a>> {
    let b = text.as_bytes();
    let (start, end, mut pos) = bracket(b, 0)?;
    let time = apache_time(input, slice(text, start, end));

    let (mut level, mut module, mut pid, mut client) = (None, None, None, None);
    while let Some((start, end, next)) = bracket(b, pos) {
        let group = slice(text, start, end);
        if let Some(rest) = group.strip_prefix("pid ") {
            pid = parse_uint(rest.split(':').next().unwrap_or("").as_bytes()).and_then(|v| u32::try_from(v).ok());
        } else if let Some(rest) = group.strip_prefix("client ") {
            client = Some(rest);
        } else if level.is_none() {
            // `module:level` in 2.4, just `level` in 2.2.
            match group.split_once(':') {
                Some((m, l)) => (module, level) = (Some(m), Some(l)),
                None => level = Some(group),
            }
        } else {
            break;
        }
        pos = next;
    }
    // Apache prints the client as `address:port`; an IPv6 address has colons of its own.
    let (remote_address, remote_port) = match client {
        Some(c) => match c.rsplit_once(':') {
            Some((a, p)) if !a.is_empty() && p.parse::<u16>().is_ok() => (Some(a), p.parse().ok()),
            _ => (Some(c), None),
        },
        None => (None, None),
    };
    Some(ErrorEntry {
        time,
        server: "apache",
        level: level?,
        module,
        pid,
        remote_address,
        remote_port,
        message: slice(text, pos, b.len()),
    })
}

fn parse_nginx_error<'a>(input: &Input, text: &'a str) -> Option<ErrorEntry<'a>> {
    let b = text.as_bytes();
    if b.get(4) != Some(&b'/')
        || b.get(7) != Some(&b'/')
        || b.get(10) != Some(&b' ')
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
    {
        return None;
    }
    let wall = secs_from_civil(four(b, 0)?, two(b, 5)?, two(b, 8)?, two(b, 11)?, two(b, 14)?, two(b, 17)?)?;
    let (start, end, mut pos) = bracket(b, 20)?;
    if b.get(19) != Some(&b' ') {
        return None;
    }
    // `pid#tid: ` precedes the message.
    let mut pid = None;
    if let Some(hash) = memchr(b'#', &b[pos..]).filter(|&h| h <= 10) {
        let tail = &b[pos + hash + 1..];
        let tid_len = tail.iter().take_while(|c| c.is_ascii_digit()).count();
        if tid_len > 0 && tail.get(tid_len..tid_len + 2) == Some(b": ") {
            pid = parse_uint(&b[pos..pos + hash]).and_then(|v| u32::try_from(v).ok());
            pos += hash + 1 + tid_len + 2;
        }
    }
    let message = slice(text, pos, b.len());
    // The first `client:` wins: the real trailer precedes the attacker-influenced request and
    // referrer fields, though an earlier message part can still carry look-alike text.
    let remote_address = message.find(", client: ").map(|i| {
        let value = &message[i + 10..];
        value.split(',').next().unwrap_or(value)
    });
    Some(ErrorEntry {
        time: Some(input.local_time(wall, 0, Precision::Seconds)),
        server: "nginx",
        level: slice(text, start, end),
        module: None,
        pid,
        remote_address,
        remote_port: None,
        message,
    })
}

fn parse_error(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut unparsed = Unparsed::default();
    for_each_line(input, |line| {
        if line.bytes.is_empty() {
            return Ok(());
        }
        let text = lossy(line.bytes);
        let entry = match line.bytes[0] {
            b'[' => parse_apache_error(input, &text),
            b'0'..=b'9' => parse_nginx_error(input, &text),
            _ => None,
        };
        match entry {
            Some(entry) => sink.emit(Loc::Offset(line.offset), &entry),
            None => {
                unparsed.note(line.offset);
                Ok(())
            }
        }
    })?;
    unparsed.report(sink);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host, with_input};
    use std::io::Write;

    fn access(name: &str) -> String {
        run(&ACCESS, "var/log/nginx/access.log", &fixture(&format!("web-access-log/{name}")), 0)
    }

    fn error(name: &str) -> String {
        run(&ERROR, "var/log/apache2/error.log", &fixture(&format!("web-error-log/{name}")), 0)
    }

    #[test]
    fn nginx_combined() {
        insta::assert_snapshot!(access("nginx-access.log"));
    }

    #[test]
    fn apache_combined() {
        insta::assert_snapshot!(access("httpd-access.log"));
    }

    #[test]
    fn debian_vhost_combined() {
        insta::assert_snapshot!(access("deb-other_vhosts_access.log"));
    }

    #[test]
    fn access_edge_cases() {
        insta::assert_snapshot!(access("edge-access.log"));
    }

    #[test]
    fn nginx_errors() {
        insta::assert_snapshot!(error("nginx-error.log"));
    }

    #[test]
    fn apache_errors() {
        insta::assert_snapshot!(error("httpd-error.log"));
    }

    #[test]
    fn error_edge_cases() {
        insta::assert_snapshot!(error("edge-error.log"));
    }

    #[test]
    fn empty_files() {
        assert_eq!(run(&ACCESS, "var/log/nginx/access.log", b"", 0), "");
        assert_eq!(run(&ERROR, "var/log/nginx/error.log", b"", 0), "");
    }

    #[test]
    fn gzip_rotation_matches_plain() {
        let plain = fixture("web-access-log/httpd-access.log");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&plain).unwrap();
        let packed = gz.finish().unwrap();
        let path = "var/log/apache2/access.log.2.gz";
        assert_eq!(run(&ACCESS, path, &packed, 0), run(&ACCESS, path, &plain, 0));
    }

    #[test]
    fn error_times_use_the_host_zone() {
        let files: &[(&str, &[u8])] = &[
            ("var/log/apache2/error.log", &fixture("web-error-log/edge-error.log")),
            ("etc/localtime", &fixture("web-error-log/New_York.tzif")),
        ];
        insta::assert_snapshot!(run_on_host(&ERROR, files, "var/log/apache2/error.log", 0));
    }

    #[test]
    fn truncated_and_flipped_input_never_panics() {
        for (artifact, name) in [(&ACCESS, "web-access-log/edge-access.log"), (&ERROR, "web-error-log/edge-error.log")]
        {
            let data = fixture(name);
            for cut in 0..=data.len() {
                with_input("var/log/nginx/x.log", &data[..cut], 0, |input| {
                    let mut sink = Sink::memory("h", artifact.id, "x", nixcavate_core::Format::Jsonl);
                    let _ = (artifact.parse)(input, &mut sink);
                });
            }
            for i in (0..data.len()).step_by(3) {
                let mut flipped = data.clone();
                flipped[i] ^= 0xa5;
                with_input("var/log/nginx/x.log", &flipped, 0, |input| {
                    let mut sink = Sink::memory("h", artifact.id, "x", nixcavate_core::Format::Jsonl);
                    let _ = (artifact.parse)(input, &mut sink);
                });
            }
        }
    }
}
