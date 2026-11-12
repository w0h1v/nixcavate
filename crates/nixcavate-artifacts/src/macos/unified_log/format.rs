//! Message rendering: printf-style format strings with os_log annotations, filled from the
//! tracepoint's data items. Format: os_log(3), printf(3), and libyal dtformats "Firehose
//! tracepoint format string" and "Value type decoders". Redacted values print `<private>`
//! and missing ones `<decode: missing data>`, as `log show` does.
//!
//! Output is bounded whatever the evidence holds: field widths and numeric precisions are
//! capped at [`MAX_WIDTH`], and a message longer than [`MAX_TEXT`] is cut and ends in `<…>`.

use super::firehose::Value;
use super::tracev3::le;
use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

#[rustfmt::skip]
const ERRNO: [&str; 106] = [
    "Operation not permitted", "No such file or directory", "No such process", "Interrupted system call",
    "Input/output error", "Device not configured", "Argument list too long", "Exec format error",
    "Bad file descriptor", "No child processes", "Resource deadlock avoided", "Cannot allocate memory",
    "Permission denied", "Bad address", "Block device required", "Resource busy", "File exists",
    "Cross-device link", "Operation not supported by device", "Not a directory", "Is a directory",
    "Invalid argument", "Too many open files in system", "Too many open files", "Inappropriate ioctl for device",
    "Text file busy", "File too large", "No space left on device", "Illegal seek", "Read-only file system",
    "Too many links", "Broken pipe", "Numerical argument out of domain", "Result too large",
    "Resource temporarily unavailable", "Operation now in progress", "Operation already in progress",
    "Socket operation on non-socket", "Destination address required", "Message too long",
    "Protocol wrong type for socket", "Protocol not available", "Protocol not supported",
    "Socket type not supported", "Operation not supported", "Protocol family not supported",
    "Address family not supported by protocol family", "Address already in use", "Can't assign requested address",
    "Network is down", "Network is unreachable", "Network dropped connection on reset",
    "Software caused connection abort", "Connection reset by peer", "No buffer space available",
    "Socket is already connected", "Socket is not connected", "Can't send after socket shutdown",
    "Too many references: can't splice", "Operation timed out", "Connection refused",
    "Too many levels of symbolic links", "File name too long", "Host is down", "No route to host",
    "Directory not empty", "Too many processes", "Too many users", "Disc quota exceeded", "Stale NFS file handle",
    "Too many levels of remote in path", "RPC struct is bad", "RPC version wrong", "RPC prog. not avail",
    "Program version wrong", "Bad procedure for program", "No locks available", "Function not implemented",
    "Inappropriate file type or format", "Authentication error", "Need authenticator", "Device power is off",
    "Device error", "Value too large to be stored in data type", "Bad executable (or shared library)",
    "Bad CPU type in executable", "Shared library version mismatch", "Malformed Mach-o file", "Operation canceled",
    "Identifier removed", "No message of desired type", "Illegal byte sequence", "Attribute not found",
    "Bad message", "EMULTIHOP (Reserved)", "No message available on STREAM", "ENOLINK (Reserved)",
    "No STREAM resources", "Not a STREAM", "Protocol error", "STREAM ioctl timeout",
    "Operation not supported on socket", "Policy not found", "State not recoverable", "Previous owner died",
    "Interface output queue is full",
];

/// The longest message (and format string) emitted, in bytes.
pub const MAX_TEXT: usize = 64 << 10;
/// The widest field width, and the largest precision of a number.
const MAX_WIDTH: usize = 1024;
/// The longest `%{...}` annotation; a `{` with no `}` within this is literal text.
const MAX_ANNOTATION: usize = 256;
/// Marks text cut short, as `log show` marks a string the tracepoint had no room for.
const CUT: &str = "<…>";

/// Cuts `text` to at most [`MAX_TEXT`] bytes, ending it with `<…>` when anything was cut.
pub fn cut(text: &mut String) {
    if text.len() > MAX_TEXT {
        let mut end = MAX_TEXT - CUT.len();
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str(CUT);
    }
}

fn strerror(errno: i64) -> String {
    match usize::try_from(errno).ok().and_then(|e| e.checked_sub(1)).and_then(|i| ERRNO.get(i)) {
        Some(text) => (*text).to_string(),
        None => format!("Unknown error: {errno}"),
    }
}

/// One conversion specification, `%{annotations}flags width .precision length conversion`.
#[derive(Default)]
struct Spec<'f> {
    /// The value decoders named in the annotations (not `public`, `private` or a name).
    decoders: [&'f str; 3],
    left: bool,
    plus: bool,
    space: bool,
    alternate: bool,
    zero: bool,
    width: Option<usize>,
    width_arg: bool,
    precision: Option<usize>,
    precision_arg: bool,
    /// Integer size in bytes from the length modifier (4 when there is none).
    size: usize,
    conversion: u8,
}

impl Spec<'_> {
    fn has(&self, decoder: &str) -> bool {
        !self.decoders[0].is_empty() && self.decoders.contains(&decoder)
    }
}

/// Parses the spec after a `%`; returns it and the bytes it used.
fn parse_spec(f: &str) -> Option<(Spec<'_>, usize)> {
    let b = f.as_bytes();
    let mut i = 0;
    let mut spec = Spec { size: 4, ..Default::default() };
    if b.first() == Some(&b'{') {
        let end = memchr::memchr(b'}', &b[..b.len().min(MAX_ANNOTATION)])?;
        let decoders = f[1..end]
            .split(',')
            .map(str::trim)
            .filter(|a| !matches!(*a, "public" | "private" | "sensitive" | "") && !a.starts_with("name="));
        for (slot, decoder) in spec.decoders.iter_mut().zip(decoders) {
            *slot = decoder;
        }
        i = end + 1;
    }
    while let Some(&c) = b.get(i) {
        match c {
            b'-' => spec.left = true,
            b'+' => spec.plus = true,
            b' ' => spec.space = true,
            b'#' => spec.alternate = true,
            b'0' => spec.zero = true,
            b'\'' => {}
            _ => break,
        }
        i += 1;
    }
    let digits = |i: &mut usize| {
        let start = *i;
        while b.get(*i).is_some_and(u8::is_ascii_digit) {
            *i += 1;
        }
        f[start..*i].parse::<usize>().ok()
    };
    if b.get(i) == Some(&b'*') {
        spec.width_arg = true;
        i += 1;
    } else {
        spec.width = digits(&mut i);
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        if b.get(i) == Some(&b'*') {
            spec.precision_arg = true;
            i += 1;
        } else {
            spec.precision = Some(digits(&mut i).unwrap_or(0));
        }
    }
    loop {
        match b.get(i)? {
            b'h' if b.get(i + 1) == Some(&b'h') => (spec.size, i) = (1, i + 2),
            b'h' => (spec.size, i) = (2, i + 1),
            b'l' | b'q' | b'j' | b'z' | b't' | b'L' => (spec.size, i) = (8, i + 1),
            _ => break,
        }
    }
    // A `%` before a non-ASCII character is literal text.
    spec.conversion = *b.get(i).filter(|c| c.is_ascii())?;
    if matches!(spec.conversion, b'D' | b'U' | b'O') {
        spec.size = 8;
    }
    Some((spec, i + 1))
}

/// The integer in `bytes`, sign-extended from its stored size and cut to the spec's size.
fn signed(bytes: &[u8], size: usize) -> i64 {
    let stored = bytes.len().clamp(1, 8);
    let v = le(bytes);
    let v = ((v << (64 - 8 * stored)) as i64) >> (64 - 8 * stored);
    match size {
        1 => v as i8 as i64,
        2 => v as i16 as i64,
        4 => v as i32 as i64,
        _ => v,
    }
}

fn unsigned(bytes: &[u8], size: usize) -> u64 {
    let v = le(bytes);
    match size {
        1 => v as u8 as u64,
        2 => v as u16 as u64,
        4 if bytes.len() <= 4 => v as u32 as u64,
        _ => v,
    }
}

fn float(bytes: &[u8]) -> f64 {
    match bytes.len() {
        4 => f32::from_bits(le(bytes) as u32) as f64,
        _ => f64::from_bits(le(bytes)),
    }
}

/// C `%e` exponent style: at least two digits and a sign.
fn c_exponent(rust: String) -> String {
    match rust.split_once('e') {
        Some((mantissa, exp)) => {
            let (sign, digits) = exp.strip_prefix('-').map_or(('+', exp), |d| ('-', d));
            format!("{mantissa}e{sign}{digits:0>2}")
        }
        None => rust,
    }
}

fn format_float(v: f64, spec: &Spec) -> String {
    if !v.is_finite() {
        let text = if v.is_nan() {
            "nan"
        } else if v > 0.0 {
            "inf"
        } else {
            "-inf"
        };
        return if spec.conversion.is_ascii_uppercase() { text.to_uppercase() } else { text.to_string() };
    }
    let precision = spec.precision.unwrap_or(6);
    let text = match spec.conversion.to_ascii_lowercase() {
        b'e' => c_exponent(format!("{v:.precision$e}")),
        b'g' => {
            let p = precision.max(1);
            let exp = if v == 0.0 {
                0
            } else {
                format!("{v:.prec$e}", prec = p - 1).split_once('e').map_or(0, |(_, e)| e.parse::<i32>().unwrap_or(0))
            };
            let mut text = if exp < -4 || exp >= p as i32 {
                c_exponent(format!("{v:.prec$e}", prec = p - 1))
            } else {
                format!("{v:.prec$}", prec = (p as i32 - 1 - exp).max(0) as usize)
            };
            if !spec.alternate {
                let (mantissa, exponent) = match text.find('e') {
                    Some(at) => text.split_at(at),
                    None => (text.as_str(), ""),
                };
                if mantissa.contains('.') {
                    text = format!("{}{exponent}", mantissa.trim_end_matches('0').trim_end_matches('.'));
                }
            }
            text
        }
        _ => format!("{v:.precision$}"),
    };
    let text = if spec.conversion.is_ascii_uppercase() { text.to_uppercase() } else { text };
    if spec.plus && v >= 0.0 {
        format!("+{text}")
    } else {
        text
    }
}

fn uuid(bytes: &[u8]) -> Option<String> {
    let uuid: &[u8; 16] = bytes.try_into().ok()?;
    Some(super::tracev3::uuid_string(uuid))
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, &b)| n | (b as u32) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() { TABLE[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

fn sockaddr(bytes: &[u8]) -> Option<String> {
    match *bytes.get(1)? {
        2 => {
            let addr: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
            Some(Ipv4Addr::from(addr).to_string())
        }
        30 => {
            let addr: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
            Some(Ipv6Addr::from(addr).to_string())
        }
        _ => None,
    }
}

/// A binary (`%P`) value through the decoders `log show` knows; hex bytes otherwise.
fn binary(bytes: &[u8], spec: &Spec) -> String {
    let decoded = if spec.has("uuid_t") {
        uuid(bytes)
    } else if spec.has("in6_addr") || spec.has("network:in6_addr") {
        <[u8; 16]>::try_from(bytes).ok().map(|a| Ipv6Addr::from(a).to_string())
    } else if spec.has("in_addr") || spec.has("network:in_addr") {
        <[u8; 4]>::try_from(bytes).ok().map(|a| Ipv4Addr::from(a).to_string())
    } else if spec.has("sockaddr") || spec.has("network:sockaddr") {
        sockaddr(bytes)
    } else if spec.has("mask.hash") {
        Some(format!("<mask.hash: '{}'>", base64(bytes)))
    } else if spec.has("mdnsresponder:domain_name") {
        domain_name(bytes)
    } else if spec.has("timeval") || spec.has("timespec") {
        timeval(bytes, spec.has("timespec"))
    } else {
        None
    };
    decoded.unwrap_or_else(|| {
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    })
}

/// A DNS name in wire format (length-prefixed labels), as `www.example.com.`.
fn domain_name(bytes: &[u8]) -> Option<String> {
    let mut name = String::new();
    let mut rest = bytes;
    while let Some((&len, tail)) = rest.split_first() {
        if len == 0 {
            break;
        }
        let label = tail.get(..len as usize)?;
        name.push_str(&String::from_utf8_lossy(label));
        name.push('.');
        rest = &tail[len as usize..];
    }
    Some(if name.is_empty() { ".".into() } else { name })
}

/// A `struct timeval` or `struct timespec` as a UTC time.
fn timeval(bytes: &[u8], nanos: bool) -> Option<String> {
    let secs = signed(bytes.get(..8)?, 8);
    let fraction = signed(bytes.get(8..12)?, 4);
    let fraction = if nanos { format!("{fraction:09}") } else { format!("{fraction:06}") };
    Some(format!("{}.{fraction}+0000", calendar(secs)))
}

/// A UTC calendar time, `YYYY-MM-DD HH:MM:SS`.
fn calendar(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = nixcavate_core::time::civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", rem / 3600, rem / 60 % 60, rem % 60)
}

/// An integer through the decoders `log show` knows, or `None` to print it plainly.
fn decoded_integer(value: &[u8], spec: &Spec) -> Option<String> {
    let v = signed(value, spec.size);
    if spec.has("bool") {
        Some(if v != 0 { "true" } else { "false" }.into())
    } else if spec.has("BOOL") {
        Some(if v != 0 { "YES" } else { "NO" }.into())
    } else if spec.has("errno") || spec.has("darwin.errno") {
        Some(format!("[{v}: {}]", strerror(v)))
    } else if spec.has("time_t") {
        Some(format!("{}+0000", calendar(v)))
    } else if spec.has("in_addr") || spec.has("network:in_addr") {
        Some(Ipv4Addr::from((unsigned(value, 4) as u32).to_le_bytes()).to_string())
    } else {
        mdns(unsigned(value, spec.size), spec)
    }
}

#[rustfmt::skip]
const RR_TYPES: [(u64, &str); 52] = [
    (1, "A"), (2, "NS"), (5, "CNAME"), (6, "SOA"), (12, "PTR"), (13, "HINFO"), (15, "MX"), (16, "TXT"), (17, "RP"),
    (18, "AFSDB"), (24, "SIG"), (25, "KEY"), (28, "AAAA"), (29, "LOC"), (33, "SRV"), (35, "NAPTR"), (36, "KX"),
    (37, "CERT"), (39, "DNAME"), (41, "OPT"), (42, "APL"), (43, "DS"), (44, "SSHFP"), (45, "IPSECKEY"),
    (46, "RRSIG"), (47, "NSEC"), (48, "DNSKEY"), (49, "DHCID"), (50, "NSEC3"), (51, "NSEC3PARAM"), (52, "TLSA"),
    (53, "SMIMEA"), (55, "HIP"), (59, "CDS"), (60, "CDNSKEY"), (61, "OPENPGPKEY"), (62, "CSYNC"), (63, "ZONEMD"),
    (64, "SVCB"), (65, "HTTPS"), (108, "EUI48"), (109, "EUI64"), (249, "TKEY"), (250, "TSIG"), (251, "IXFR"),
    (252, "AXFR"), (255, "ANY"), (256, "URI"), (257, "CAA"), (32768, "TA"), (32769, "DLV"), (65535, "Reserved"),
];

/// DNS header flags as mDNSResponder's decoder prints them.
fn dns_flags(flags: u64) -> String {
    const OPCODES: [&str; 7] = ["Query", "IQuery", "Status", "3", "Notify", "Update", "DSO"];
    const RCODES: [&str; 11] = [
        "NoError", "FormErr", "ServFail", "NXDomain", "NotImp", "Refused", "YXDomain", "YXRRSet", "NXRRSet", "NotAuth",
        "NotZone",
    ];
    let opcode = (flags >> 11 & 0xf) as usize;
    let mut text = format!("0x{flags:04X} ({}/", if flags & 0x8000 != 0 { "R" } else { "Q" });
    let _ = write!(text, "{}", OPCODES.get(opcode).map_or(opcode.to_string(), |o| o.to_string()));
    for (bit, name) in [(0x400, "AA"), (0x200, "TC"), (0x100, "RD"), (0x80, "RA"), (0x20, "AD"), (0x10, "CD")] {
        if flags & bit != 0 {
            let _ = write!(text, ", {name}");
        }
    }
    let rcode = (flags & 0xf) as usize;
    let _ = write!(text, ", {})", RCODES.get(rcode).map_or(rcode.to_string(), |r| r.to_string()));
    text
}

/// A duration in seconds, `1h 2m 3s`.
fn duration(secs: u64) -> String {
    let parts = [(secs / 86_400, "d"), (secs / 3600 % 24, "h"), (secs / 60 % 60, "m"), (secs % 60, "s")];
    let text: Vec<String> = parts.iter().filter(|p| p.0 > 0).map(|(v, unit)| format!("{v}{unit}")).collect();
    if text.is_empty() {
        "0s".into()
    } else {
        text.join(" ")
    }
}

/// mDNSResponder's decoders (libyal dtformats "mDNS ..." sections).
fn mdns(v: u64, spec: &Spec) -> Option<String> {
    let pick = |yes: &str, no: &str| Some(if v != 0 { yes } else { no }.to_string());
    if spec.has("mdns:rrtype") {
        Some(RR_TYPES.iter().find(|t| t.0 == v).map_or_else(|| format!("TYPE{v}"), |t| t.1.to_string()))
    } else if spec.has("mdns:yesno") {
        pick("yes", "no")
    } else if spec.has("mdns:addrmv") {
        pick("add", "rmv")
    } else if spec.has("mdns:acceptable") {
        pick("acceptable", "unacceptable")
    } else if spec.has("mdns:time_duration") {
        Some(duration(v))
    } else if spec.has("mdns:dns.idflags") {
        let id = v >> 16 & 0xffff;
        Some(format!("id: 0x{id:04X} ({id}), flags: {}", dns_flags(v & 0xffff)))
    } else if spec.has("mdns:dns.counts") {
        Some(format!("{}/{}/{}/{}", v >> 48, v >> 32 & 0xffff, v >> 16 & 0xffff, v & 0xffff))
    } else if spec.has("mdns:protocol") {
        Some(match v {
            1 => "UDP".into(),
            2 => "TCP".into(),
            4 => "HTTPS".into(),
            _ => v.to_string(),
        })
    } else if spec.has("network:tcp_state") {
        const STATES: [&str; 11] = [
            "CLOSED",
            "LISTEN",
            "SYN_SENT",
            "SYN_RECEIVED",
            "ESTABLISHED",
            "CLOSE_WAIT",
            "FIN_WAIT_1",
            "CLOSING",
            "LAST_ACK",
            "FIN_WAIT_2",
            "TIME_WAIT",
        ];
        Some(STATES.get(v as usize).map_or_else(|| v.to_string(), |s| s.to_string()))
    } else if spec.has("network:tcp_flags") {
        let names =
            [(0x01, 'F'), (0x02, 'S'), (0x04, 'R'), (0x08, 'P'), (0x20, 'U'), (0x40, 'E'), (0x80, 'W'), (0x10, '.')];
        Some(format!("[{}]", names.iter().filter(|f| v & f.0 != 0).map(|f| f.1).collect::<String>()))
    } else if spec.has("mdnsresponder:dns_scope_type") {
        Some(match v {
            0 => "Unscoped".into(),
            1 => "Interface scoped".into(),
            2 => "Service scoped".into(),
            _ => v.to_string(),
        })
    } else {
        None
    }
}

fn integer(value: &[u8], spec: &Spec) -> String {
    let (negative, digits) = match spec.conversion {
        b'd' | b'i' | b'D' => {
            let v = signed(value, spec.size);
            (v < 0, v.unsigned_abs().to_string())
        }
        b'x' | b'p' => (false, format!("{:x}", unsigned(value, if spec.conversion == b'p' { 8 } else { spec.size }))),
        b'X' => (false, format!("{:X}", unsigned(value, spec.size))),
        b'o' | b'O' => (false, format!("{:o}", unsigned(value, spec.size))),
        b'c' | b'C' => return char::from_u32(unsigned(value, 4) as u32).unwrap_or('?').to_string(),
        _ => (false, unsigned(value, spec.size).to_string()),
    };
    let digits = match spec.precision {
        Some(p) if digits.len() < p => format!("{digits:0>p$}"),
        Some(0) if digits == "0" => String::new(),
        _ => digits,
    };
    let prefix = match spec.conversion {
        b'p' => "0x",
        b'x' if spec.alternate && !digits.trim_start_matches('0').is_empty() => "0x",
        b'X' if spec.alternate && !digits.trim_start_matches('0').is_empty() => "0X",
        b'o' if spec.alternate && !digits.starts_with('0') => "0",
        _ if negative => "-",
        b'd' | b'i' | b'D' if spec.plus => "+",
        b'd' | b'i' | b'D' if spec.space => " ",
        _ => "",
    };
    // Zero padding goes between the sign or prefix and the digits.
    match spec.width {
        Some(w) if spec.zero && !spec.left && spec.precision.is_none() && prefix.len() + digits.len() < w => {
            format!("{prefix}{digits:0>width$}", width = w - prefix.len())
        }
        _ => format!("{prefix}{digits}"),
    }
}

fn text(bytes: &[u8], spec: &Spec) -> String {
    let bytes = &bytes[..bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1)];
    let bytes = match spec.precision {
        Some(p) if spec.conversion != b'@' && p < bytes.len() => &bytes[..p],
        _ => bytes,
    };
    std::str::from_utf8(bytes).map_or_else(|_| String::from_utf8_lossy(bytes).into_owned(), str::to_string)
}

/// A JSON string literal, for locationd's `escape_only` decoder.
fn escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' | '\\' | '/' => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn pad(out: &mut String, body: &str, spec: &Spec) {
    let len = body.chars().count();
    match spec.width {
        Some(w) if w > len && spec.left => {
            out.push_str(body);
            out.extend(std::iter::repeat_n(' ', w - len));
        }
        Some(w) if w > len => {
            out.extend(std::iter::repeat_n(' ', w - len));
            out.push_str(body);
        }
        _ => out.push_str(body),
    }
}

/// Renders `format` with `items` into `out`, at most [`MAX_TEXT`] bytes of it. Conversions
/// with no item left print `missing`.
pub fn render(format: &str, items: &[Value], missing: &str, out: &mut String) {
    let mut items = items.iter();
    let mut rest = format;
    while let Some(at) = memchr::memchr(b'%', rest.as_bytes()) {
        if out.len() > MAX_TEXT {
            break;
        }
        out.push_str(&rest[..at]);
        rest = &rest[at + 1..];
        if let Some(after) = rest.strip_prefix('%') {
            out.push('%');
            rest = after;
            continue;
        }
        let Some((mut spec, used)) = parse_spec(rest) else {
            out.push('%');
            continue;
        };
        let original = &rest[..used];
        rest = &rest[used..];
        if spec.conversion == b'n' {
            continue;
        }
        if !b"diDuUoOxXpcCfFeEgGaAsS@Pm".contains(&spec.conversion) {
            out.push('%');
            out.push_str(original);
            continue;
        }
        // `*` widths and precisions, and precisions recorded for `%.Ns`, come first.
        let star = |field: &mut Option<usize>, items: &mut std::slice::Iter<Value>| {
            let v = match items.as_slice().first() {
                Some(Value::Precision(v)) => *v as usize,
                Some(Value::Number(b)) => signed(b, 4).max(0) as usize,
                _ => return,
            };
            items.next();
            *field = Some(v);
        };
        if spec.width_arg {
            star(&mut spec.width, &mut items);
        }
        if spec.precision_arg {
            star(&mut spec.precision, &mut items);
        }
        while let Some(Value::Precision(v)) = items.as_slice().first() {
            if spec.precision.is_some() && !spec.precision_arg {
                spec.precision = Some(*v as usize);
            }
            items.next();
        }
        let Some(item) = items.next() else {
            out.push_str(missing);
            continue;
        };
        // Widths, and the precisions of numbers, pad, so they are capped; the precision of
        // string data only limits it.
        spec.width = spec.width.map(|w| w.min(MAX_WIDTH));
        if !matches!(item, Value::Bytes(_) | Value::Truncated(_)) {
            spec.precision = spec.precision.map(|p| p.min(MAX_WIDTH));
        }
        // Values shown through a decoder, and redacted ones, are not padded to the width.
        let mut decoded = false;
        let body = match *item {
            Value::Private => {
                decoded = true;
                "<private>".to_string()
            }
            Value::Precision(_) => continue, // precisions were taken above
            Value::Number(bytes) => match spec.conversion {
                b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => format_float(float(bytes), &spec),
                b'm' => strerror(signed(bytes, 4)),
                _ => match decoded_integer(bytes, &spec) {
                    Some(text) => {
                        decoded = true;
                        text
                    }
                    None if b"sS@P".contains(&spec.conversion) => integer(bytes, &Spec { conversion: b'd', ..spec }),
                    None => integer(bytes, &spec),
                },
            },
            Value::Truncated(bytes) => format!("{}<…>", text(bytes, &spec)),
            Value::Bytes(None) if spec.has("mask.hash") => "<mask.hash: (null)>".to_string(),
            Value::Bytes(None) if spec.has("location:escape_only") => String::new(),
            Value::Bytes(None) => "(null)".to_string(),
            Value::Bytes(Some(bytes)) => match spec.conversion {
                b'P' => binary(bytes, &spec),
                _ if spec.has("mask.hash") => binary(bytes, &spec),
                _ if spec.has("location:escape_only") => escaped(&text(bytes, &spec)),
                _ => text(bytes, &spec),
            },
        };
        // Signpost metadata is wrapped in markup that Instruments parses.
        let markup = spec.decoders.iter().find_map(|a| {
            ["signpost.description:", "signpost.telemetry:"]
                .iter()
                .find_map(|p| a.strip_prefix(p).map(|k| (&p[..p.len() - 1], k)))
        });
        match markup {
            Some((namespace, key)) if !matches!(item, Value::Private) => {
                let _ = write!(out, "__##__{namespace}#____#{key}#_##_#{body}##__##");
            }
            _ if decoded => out.push_str(&body),
            _ => pad(out, &body, &spec),
        }
    }
    if out.len() <= MAX_TEXT {
        out.push_str(rest);
    }
    cut(out);
}

/// A property list value as Foundation's `description` shows it (and so `log show` shows a
/// statedump): old-style plist text, 4-space indents, dictionary keys sorted, a container
/// inside a container indented once more on its first line. Inside a container every value
/// is shown as text and quoted unless it is only letters and digits; a value on its own is
/// not quoted. Stops adding once `out` holds more than [`MAX_TEXT`] bytes.
pub fn description(value: &plist::Value, level: usize, out: &mut String) {
    use plist::Value as P;
    let indent = |out: &mut String, n: usize| out.extend(std::iter::repeat_n("    ", n));
    let nested = |value: &P| matches!(value, P::Array(_) | P::Dictionary(_));
    if out.len() > MAX_TEXT {
        return;
    }
    match value {
        P::Dictionary(dict) => {
            let mut entries: Vec<_> = dict.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            out.push_str("{\n");
            for (key, value) in entries {
                if out.len() > MAX_TEXT {
                    break;
                }
                indent(out, level + 1);
                quoted(key, out);
                out.push_str(" = ");
                if nested(value) {
                    indent(out, level + 1);
                }
                description(value, level + 1, out);
                out.push_str(";\n");
            }
            indent(out, level);
            out.push('}');
        }
        P::Array(array) => {
            out.push_str("(\n");
            for (i, value) in array.iter().enumerate() {
                if out.len() > MAX_TEXT {
                    break;
                }
                indent(out, level + 1);
                if nested(value) {
                    indent(out, level + 1);
                }
                description(value, level + 1, out);
                out.push_str(if i + 1 < array.len() { ",\n" } else { "\n" });
            }
            indent(out, level);
            out.push(')');
        }
        P::Data(bytes) => {
            // Short data in full; longer data as its first 16 and last 8 bytes, in groups of
            // 4. (The archive shows 21 bytes in full and 40 abbreviated; 24 is assumed.)
            let hex = |out: &mut String, bytes: &[u8]| {
                for group in bytes.chunks(4) {
                    group.iter().for_each(|b| {
                        let _ = write!(out, "{b:02x}");
                    });
                    out.push(' ');
                }
            };
            let _ = write!(out, "{{length = {}, bytes = 0x", bytes.len());
            if bytes.len() <= 24 {
                bytes.iter().for_each(|b| {
                    let _ = write!(out, "{b:02x}");
                });
            } else {
                hex(out, &bytes[..16]);
                out.push_str("... ");
                hex(out, &bytes[bytes.len() - 8..]);
            }
            out.push('}');
        }
        scalar => {
            let text = match scalar {
                P::String(text) => text.clone(),
                P::Boolean(v) => if *v { "1" } else { "0" }.to_string(),
                P::Integer(v) => match v.as_signed() {
                    Some(v) => v.to_string(),
                    None => v.as_unsigned().unwrap_or_default().to_string(),
                },
                // `%.16g`, as NSNumber shows a double.
                P::Real(v) => format_float(*v, &Spec { conversion: b'g', precision: Some(16), ..Default::default() }),
                P::Date(date) => {
                    let secs = std::time::SystemTime::from(*date)
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or_else(|e| -(e.duration().as_secs() as i64), |d| d.as_secs() as i64);
                    format!("{} +0000", calendar(secs))
                }
                P::Uid(uid) => format!("{{value = {}}}", uid.get()),
                _ => "<unknown>".to_string(),
            };
            if level == 0 {
                out.push_str(&text);
            } else {
                quoted(&text, out);
            }
        }
    }
}

/// A string inside a `description`: bare when it is only ASCII letters and digits; quoted
/// otherwise, with quotes, backslashes, control and non-ASCII characters escaped.
fn quoted(text: &str, out: &mut String) {
    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_alphanumeric()) {
        out.push_str(text);
        return;
    }
    out.push('"');
    for c in text.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 || !c.is_ascii() => {
                let _ = write!(out, "\\U{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
