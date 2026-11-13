//! The line header of ESXi's text logs. ESXi writes them through its own `vmsyslogd`, so they
//! do not look like the syslog files of other systems: there is no host name. Layouts seen:
//!
//! - 6.x and 7.x: `2025-12-09T04:04:13.227Z warning hostd[2099429] [Originator@6876 sub=...] text`
//!   for the VMware daemons, `2001-01-01T01:37:20Z shell[2100700]: [root]: ls` for the rest, and
//!   `2025-12-27T00:20:40.756Z cpu23:2098417)Elf: 2101: ...` for the VMkernel;
//! - 8.0: `2026-04-03T23:16:33.976Z In(14) shell[132915]: [root]: ls` and
//!   `2022-06-02T02:56:51.118Z Db(167) Hostd[1001392583]: [Originator@6876 ...] text`, with a
//!   two-letter severity (`Em Al Cr Er Wa No In Db`) and the syslog priority in parentheses.
//!
//! Times are UTC with a `Z`. VMware does not publish these layouts; they were derived from real
//! public logs (listed in `docs/LIMITATIONS.md`) and cross-checked with the community `lnav` format
//! definitions (`vmk_log.json`, `vmw_log.json` and `esx_syslog_log.json` at
//! <https://github.com/tstack/lnav/tree/master/src/formats>), whose sample lines were read, not copied.

use crate::Input;
use nixcavate_core::time::{parse_iso8601, parse_uint};
use nixcavate_core::Timestamp;

/// The parts every layout shares.
pub struct Header<'a> {
    pub time: Option<Timestamp>,
    /// Severity, spelled the same in every version: `error`, `warning`, `info`, `debug`...
    /// Empty when the line states none.
    pub level: &'a str,
    pub program: &'a str,
    pub pid: Option<u32>,
    /// What follows the header.
    pub message: &'a str,
}

/// Words the VMware daemons (hostd, vpxa, rhttpproxy...) use for a level in 6.x and 7.x.
const LEVEL_WORDS: [&str; 12] =
    ["panic", "alert", "crit", "critical", "error", "warning", "warn", "notice", "info", "verbose", "debug", "quiet"];

pub fn header<'a>(input: &Input, line: &'a str) -> Header<'a> {
    let mut out = Header { time: None, level: "", program: "", pid: None, message: line };
    let Some((parsed, used)) = parse_iso8601(line.as_bytes()) else { return out };
    out.time = Some(parsed.recorded().unwrap_or_else(|| input.local_time(parsed.secs, parsed.nanos, parsed.precision)));
    let Some(after) = line.get(used..) else { return out };
    // `2025-12-08T11:31:14.114Z: text` (vobd) has a colon, the rest a space.
    let Some(mut rest) = after.strip_prefix(": ").or_else(|| after.strip_prefix(' ')) else {
        out.message = after.trim_start_matches(':').trim_start();
        return out;
    };
    let (first, tail) = split_word(rest);
    if let Some(level) = severity_code(first) {
        out.level = level;
        rest = tail;
    } else if LEVEL_WORDS.contains(&first) && tag(split_word(tail).0).is_some_and(|(_, pid)| pid.is_some()) {
        out.level = first;
        rest = tail;
    }
    let (word, tail) = split_word(rest);
    match tag(word) {
        Some((program, pid)) => {
            out.program = program;
            out.pid = pid;
            out.message = tail;
        }
        None => out.message = rest,
    }
    out
}

/// `In(14)`, `Db(167)`, `Wa(12)[+]`: the two-letter severity of ESXi 8.
fn severity_code(word: &str) -> Option<&'static str> {
    let word = word.strip_suffix("[+]").or_else(|| word.strip_suffix('+')).unwrap_or(word);
    let (code, number) = word.split_once('(')?;
    let number = number.strip_suffix(')')?;
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(match code {
        "Em" => "emergency",
        "Al" => "alert",
        "Cr" => "critical",
        "Er" => "error",
        "Wa" => "warning",
        "No" => "notice",
        "In" => "info",
        "Db" => "debug",
        _ => return None,
    })
}

/// `name[123]:`, `name[123]`, `name:` or `-[123]`: a program and its process id. A `-` name
/// (hostd's startup lines) gives an empty program.
fn tag(word: &str) -> Option<(&str, Option<u32>)> {
    let colon = word.ends_with(':');
    let word = word.strip_suffix(':').unwrap_or(word);
    let (name, pid) = match word.split_once('[') {
        Some((name, rest)) => {
            let digits = rest.strip_suffix(']')?;
            (name, Some(u32::try_from(parse_uint(digits.as_bytes())?).ok()?))
        }
        // A bare `name` is a program only when the colon said so.
        None if colon => (word, None),
        None => return None,
    };
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '/');
    if name.is_empty() || name.len() > 64 || !name.chars().all(plain) {
        return None;
    }
    Some((if name == "-" { "" } else { name }, pid))
}

fn split_word(text: &str) -> (&str, &str) {
    text.split_once(' ').unwrap_or((text, ""))
}

/// The `[Originator@6876 sub=Component opID=... user=...]` block of the VMware daemons. A value
/// may hold spaces (`sub=Proxy Req 00512`), so a word without `=` continues the previous value.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Structured<'a> {
    pub component: &'a str,
    pub op_id: &'a str,
    pub user: &'a str,
    pub session: &'a str,
}

/// Splits a message into its structured block and the text after it.
pub fn structured(message: &str) -> (Structured<'_>, &str) {
    let mut out = Structured::default();
    let Some(inner) = message.strip_prefix('[') else { return (out, message) };
    let Some(end) = inner.find(']') else { return (out, message) };
    if !inner.starts_with("Originator@") && !inner.starts_with("opI") {
        return (out, message);
    }
    let block = &inner[..end];
    // Each value is the slice from its first byte to the start of the next key.
    let mut keys: Vec<(&str, usize, usize)> = Vec::new();
    let mut pos = 0;
    for word in block.split(' ') {
        let at = pos;
        pos += word.len() + 1;
        if let Some((key, _)) = word.split_once('=') {
            if !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric()) {
                keys.push((key, at + key.len() + 1, block.len().min(pos.saturating_sub(1))));
                continue;
            }
        }
        if let Some(last) = keys.last_mut() {
            last.2 = block.len().min(pos.saturating_sub(1));
        }
    }
    for (key, from, to) in keys {
        let value = block.get(from..to).unwrap_or_default();
        match key {
            "sub" => out.component = value,
            "opID" | "opId" => out.op_id = value,
            "user" => out.user = value,
            "sid" => out.session = value,
            _ => {}
        }
    }
    (out, inner[end + 1..].trim_start())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::with_input;

    fn head(line: &str) -> (Option<String>, String, String, Option<u32>, String) {
        with_input("var/run/log/x.log", b"x", 0, |input| {
            let h = header(input, line);
            (h.time.map(|t| t.to_rfc3339()), h.level.into(), h.program.into(), h.pid, h.message.into())
        })
    }

    #[test]
    fn esxi_6_and_7_layouts() {
        let (t, level, program, pid, msg) = head("2001-01-01T01:37:20Z shell[2100700]: [root]: vmware -v");
        assert_eq!(
            (t.as_deref(), &*level, &*program, pid, &*msg),
            (Some("2001-01-01T01:37:20Z"), "", "shell", Some(2100700), "[root]: vmware -v")
        );
        let (t, level, program, pid, msg) =
            head("2025-12-09T04:04:13.227Z warning hostd[2099429] [Originator@6876 sub=X] text");
        assert_eq!(
            (t.as_deref(), &*level, &*program, pid, &*msg),
            (Some("2025-12-09T04:04:13.227Z"), "warning", "hostd", Some(2099429), "[Originator@6876 sub=X] text")
        );
        let (_, level, program, pid, msg) =
            head("2025-12-09T04:04:13.227Z info -[2101065] [Originator@6876 sub=Default] x");
        assert_eq!((&*level, &*program, pid, &*msg), ("info", "", Some(2101065), "[Originator@6876 sub=Default] x"));
        let (_, level, program, _, msg) = head("2025-12-27T00:20:40.756Z cpu23:2098417)Elf: 2101: module x");
        assert_eq!((&*level, &*program, &*msg), ("", "", "cpu23:2098417)Elf: 2101: module x"));
        let (t, _, program, _, msg) = head("2025-12-08T11:31:14.114Z: [netCorrelator] 22427618us: [vob.x] text");
        assert_eq!((t.is_some(), &*program, &*msg), (true, "", "[netCorrelator] 22427618us: [vob.x] text"));
    }

    #[test]
    fn esxi_8_layout_with_severity_codes() {
        let (t, level, program, pid, msg) = head("2026-04-03T23:16:33.976Z In(14) shell[132915]: [root]: ls");
        assert_eq!(
            (t.as_deref(), &*level, &*program, pid, &*msg),
            (Some("2026-04-03T23:16:33.976Z"), "info", "shell", Some(132915), "[root]: ls")
        );
        let (_, level, program, _, msg) =
            head("2022-06-02T02:56:51.118Z Db(167) Hostd[1001392583]: [Originator@6876 sub=A] x");
        assert_eq!((&*level, &*program, &*msg), ("debug", "Hostd", "[Originator@6876 sub=A] x"));
        let (_, level, program, pid, _) = head("2026-04-03T23:05:57.063Z Er(11) Jumper2[131350]: error x");
        assert_eq!((&*level, &*program, pid), ("error", "Jumper2", Some(131350)));
        let (_, level, program, _, msg) = head("2023-08-08T14:13:55Z In(182) vmkernel: VMB: 65: Reserved 4 MPNs");
        assert_eq!((&*level, &*program, &*msg), ("info", "vmkernel", "VMB: 65: Reserved 4 MPNs"));
        let (_, level, program, _, msg) = head("2022-06-01T13:42:40.681Z In(05) host-16250 <analytics> Skip");
        assert_eq!((&*level, &*program, &*msg), ("info", "", "host-16250 <analytics> Skip"));
    }

    #[test]
    fn lines_without_a_time_keep_their_text() {
        let (t, level, program, _, msg) = head("0:00:00:05.344 cpu0:2097152)WARNING: VTD: 715: x");
        assert_eq!((t, &*level, &*program, &*msg), (None, "", "", "0:00:00:05.344 cpu0:2097152)WARNING: VTD: 715: x"));
        for line in
            ["", "2025", "2025-12-09T04:04:13Z", "2025-12-09T04:04:13Z ", "2025-12-09T04:04:13Z x[", "\u{e9}\u{e9}"]
        {
            head(line);
        }
    }

    #[test]
    fn structured_block_values_may_hold_spaces() {
        let (s, text) = structured("[Originator@6876 sub=Proxy Req 00512 opID=esxui-18d5-756b user=root] Resolved");
        assert_eq!((s.component, s.op_id, s.user, text), ("Proxy Req 00512", "esxui-18d5-756b", "root", "Resolved"));
        let (s, text) = structured(
            "[Originator@6876 sub=AdapterServer opID=531c52d7-9d8a sid=52806149 user=vpxuser:<no user>] New request",
        );
        assert_eq!(
            (s.component, s.session, s.user, text),
            ("AdapterServer", "52806149", "vpxuser:<no user>", "New request")
        );
        let (s, text) = structured("[Originator@6876 sub=Default] x");
        assert_eq!((s.component, s.op_id, text), ("Default", "", "x"));
        let (s, text) = structured("[ESXShell] not a block");
        assert_eq!((s, text), (Structured::default(), "[ESXShell] not a block"));
        for hostile in [
            "[",
            "[Originator@",
            "[Originator@6876 =]",
            "[Originator@6876 sub=]",
            "[Originator@6876 sub=\u{e9}\u{e9} a=b",
        ] {
            structured(hostile);
        }
    }
}
