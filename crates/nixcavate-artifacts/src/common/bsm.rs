//! BSM audit trails (OpenBSM): `/var/audit/*` on FreeBSD, `/var/audit/*` on macOS (under
//! `private/`), and Solaris `var/audit/*/files/*`. Format: audit.log(5) and the OpenBSM
//! `audit_record.h` token numbers, with the layouts checked against `praudit(1)` output of
//! real FreeBSD trails (see docs/LIMITATIONS.md for the numbers).
//!
//! A trail is a series of records. Each record starts with a header token that carries the
//! length of the whole record, so a record whose tokens are not understood is skipped as a
//! unit and the next one is still read. Every integer is big-endian. A trail may begin and
//! end with a file token (`AUT_OTHER_FILE32`) naming the file it continues or was continued by.
//!
//! The mapping from event numbers to names is data (`bsm_data/audit_event.*`), taken from
//! each system's own `/etc/security/audit_event`, and is chosen by the host's operating
//! system: macOS and FreeBSD agree on the low numbers and differ above them, and Solaris
//! uses its own table (not shipped: its events are shown by number only).
//!
//! Validated against FreeBSD only. A macOS trail needs root to produce; macOS is covered by
//! the same parser and a synthetic fixture (docs/LIMITATIONS.md, "Synthetic only").

use crate::text::lossy;
use crate::{Artifact, Category, Input};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use nixcavate_source::Os;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

pub const ARTIFACT: Artifact = Artifact::new(
    "bsm-audit",
    "BSM audit trails (OpenBSM / Solaris audit): logins, execs, file and process events",
    Category::Logs,
    &[Os::FreeBsd, Os::Macos, Os::Solaris],
    &["var/audit/*", "private/var/audit/*", "var/share/audit/*", "var/audit/*/files/*", "var/share/audit/*/files/*"],
    parse,
);

// ---- the event and class tables ----

struct EventInfo<'t> {
    name: &'t str,
    description: &'t str,
    classes: &'t str,
}

type EventTable<'t> = BTreeMap<u32, EventInfo<'t>>;

fn table(text: &str) -> EventTable<'_> {
    let mut events = EventTable::new();
    for line in text.lines() {
        // `id:AUE_name:description:class,class`; the description may hold a colon.
        let Some((id, rest)) = line.split_once(':') else { continue };
        let Some((name, rest)) = rest.split_once(':') else { continue };
        let Some((description, classes)) = rest.rsplit_once(':') else { continue };
        if let Ok(id) = id.trim().parse() {
            events.insert(id, EventInfo { name, description, classes });
        }
    }
    events
}

fn events_for(os: Os) -> Option<&'static EventTable<'static>> {
    static FREEBSD: OnceLock<EventTable<'static>> = OnceLock::new();
    static MACOS: OnceLock<EventTable<'static>> = OnceLock::new();
    match os {
        Os::FreeBsd => Some(FREEBSD.get_or_init(|| table(include_str!("bsm_data/audit_event.freebsd")))),
        Os::Macos => Some(MACOS.get_or_init(|| table(include_str!("bsm_data/audit_event.macos")))),
        // Solaris and illumos number the same events differently: their table is read from the
        // evidence (`etc/security/audit_event`), which every such host has.
        _ => None,
    }
}

// ---- token ids (OpenBSM audit_record.h) ----

const AUT_OTHER_FILE32: u8 = 0x11;
const AUT_TRAILER: u8 = 0x13;
const AUT_HEADER32: u8 = 0x14;
const AUT_HEADER32_EX: u8 = 0x15;
/// Solaris and illumos: the service (`svc:/network/ssh:default`) an SMF event is about.
const AUT_FMRI: u8 = 0x20;
const AUT_IPC: u8 = 0x22;
const AUT_PATH: u8 = 0x23;
const AUT_SUBJECT32: u8 = 0x24;
const AUT_PROCESS32: u8 = 0x26;
const AUT_RETURN32: u8 = 0x27;
const AUT_TEXT: u8 = 0x28;
const AUT_OPAQUE: u8 = 0x29;
const AUT_IN_ADDR: u8 = 0x2a;
const AUT_IP: u8 = 0x2b;
const AUT_IPORT: u8 = 0x2c;
const AUT_ARG32: u8 = 0x2d;
const AUT_SOCKET: u8 = 0x2e;
const AUT_SEQ: u8 = 0x2f;
const AUT_ATTR: u8 = 0x31;
const AUT_IPC_PERM: u8 = 0x32;
const AUT_GROUPS: u8 = 0x34;
/// Solaris and illumos: a user id and name (`54,104,bob` in `praudit -r`).
const AUT_USER: u8 = 0x36;
/// Use of a privilege: a success flag and the privilege set.
const AUT_UPRIV: u8 = 0x39;
const AUT_NEWGROUPS: u8 = 0x3b;
const AUT_EXEC_ARGS: u8 = 0x3c;
const AUT_EXEC_ENV: u8 = 0x3d;
const AUT_ATTR32: u8 = 0x3e;
/// Solaris and illumos: use of an authorization (`solaris.smf.modify`).
const AUT_UAUTH: u8 = 0x3f;
const AUT_CMD: u8 = 0x51;
const AUT_EXIT: u8 = 0x52;
const AUT_ZONENAME: u8 = 0x60;
const AUT_HOST: u8 = 0x70;
const AUT_ARG64: u8 = 0x71;
const AUT_RETURN64: u8 = 0x72;
const AUT_ATTR64: u8 = 0x73;
const AUT_HEADER64: u8 = 0x74;
const AUT_SUBJECT64: u8 = 0x75;
const AUT_PROCESS64: u8 = 0x77;
const AUT_OTHER_FILE64: u8 = 0x78;
const AUT_HEADER64_EX: u8 = 0x79;
const AUT_SUBJECT32_EX: u8 = 0x7a;
const AUT_PROCESS32_EX: u8 = 0x7b;
const AUT_SUBJECT64_EX: u8 = 0x7c;
const AUT_PROCESS64_EX: u8 = 0x7d;
const AUT_IN_ADDR_EX: u8 = 0x7e;
const AUT_SOCKET_EX: u8 = 0x7f;
const AUT_SOCKINET32: u8 = 0x80;
const AUT_SOCKINET128: u8 = 0x81;
const AUT_SOCKUNIX: u8 = 0x82;

/// The trailer's magic number.
const TRAILER_MAGIC: u16 = 0xb105;
/// The smallest header (32-bit times) plus trailer: a record cannot be shorter.
const MIN_RECORD: usize = 18 + 7;
/// The largest record the kernel writes is far below this; a longer claim is a damaged header.
const MAX_RECORD: usize = 16 << 20;
/// The most strings, arguments or paths kept per record.
const MAX_ITEMS: usize = 4096;
/// A string longer than this in one record is cut for output.
const MAX_STRING: usize = 4096;

fn is_header(id: u8) -> bool {
    matches!(id, AUT_HEADER32 | AUT_HEADER32_EX | AUT_HEADER64 | AUT_HEADER64_EX)
}

// ---- reading ----

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }
    fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.bytes(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.bytes(4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        self.bytes(8).map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
    /// A 16-bit length followed by that many bytes, the last usually a NUL.
    fn counted(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.bytes(n.into())
    }
    /// An address of the given length in bytes (4 or 16).
    fn address(&mut self, length: u32) -> Option<String> {
        match length {
            4 => self.bytes(4).map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()),
            16 => {
                let b = self.bytes(16)?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(b);
                Some(Ipv6Addr::from(octets).to_string())
            }
            _ => None,
        }
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.bytes(n).map(|_| ())
    }
}

/// Text up to the first NUL, cut at a sane length.
fn string(bytes: &[u8]) -> Cow<'_, str> {
    let end = memchr::memchr(0, bytes).unwrap_or(bytes.len()).min(MAX_STRING);
    lossy(&bytes[..end])
}

// ---- the record ----

#[derive(Serialize, Default)]
struct Audit<'a> {
    time: Option<Timestamp>,
    /// `record` for an event, `file` for the file token that opens or closes a trail.
    kind: &'static str,
    event_id: u32,
    /// The `AUE_` name from the host's `audit_event` table; empty when the number is unknown.
    event: &'a str,
    event_description: &'a str,
    /// Audit classes of the event (`lo`, `aa`, `ex`, ...).
    event_classes: &'a str,
    event_modifier: u16,
    version: u8,
    record_bytes: u32,
    /// The machine that wrote the record, when the header says (extended headers).
    machine: String,
    audit_user_id: Option<u32>,
    effective_user_id: Option<u32>,
    effective_group_id: Option<u32>,
    real_user_id: Option<u32>,
    real_group_id: Option<u32>,
    process_id: Option<u32>,
    session_id: Option<u32>,
    terminal_port: Option<u64>,
    terminal_address: String,
    /// `success` or `failure` from the return token; empty when the record has none.
    result: &'static str,
    /// The error number of the return token (0 for success).
    return_status: Option<u8>,
    return_value: Option<u64>,
    paths: Vec<Cow<'a, str>>,
    text: Vec<Cow<'a, str>>,
    /// `NAME=VALUE (ARG#N)` for each arg token.
    arguments: Vec<String>,
    exec_args: Vec<Cow<'a, str>>,
    exec_env: Vec<Cow<'a, str>>,
    attribute_mode: Option<u32>,
    attribute_user_id: Option<u32>,
    attribute_group_id: Option<u32>,
    attribute_node_id: Option<u64>,
    socket: Vec<String>,
    /// The processes named by process tokens (the target of a signal, for example).
    target_processes: Vec<String>,
    sequence: Option<u32>,
    zone: String,
    /// `UID NAME` for each user token (Solaris and illumos: the account a record is about).
    users: Vec<String>,
    /// Privileges used, each followed by ` (failed)` when the use was refused.
    privileges: Vec<String>,
    /// Authorizations used (`solaris.smf.modify`).
    authorizations: Vec<Cow<'a, str>>,
    /// Service names (FMRI) from Solaris and illumos service management events.
    services: Vec<Cow<'a, str>>,
    /// The names of the tokens the record holds, in order.
    tokens: Vec<&'static str>,
    #[serde(skip)]
    failed: bool,
}

impl Record for Audit<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let Some(time) = self.time else { return None.into_iter() };
        let who = self
            .audit_user_id
            .filter(|&id| id != u32::MAX)
            .map_or_else(|| format!("uid {}", self.effective_user_id.unwrap_or(0)), |id| format!("audit user {id}"));
        let first = |v: &[Cow<'_, str>]| v.first().map(|s| s.to_string()).unwrap_or_default();
        let command = || {
            let args = self.exec_args.join(" ");
            if args.is_empty() {
                first(&self.paths)
            } else {
                args
            }
        };
        let outcome = if self.failed { " (failed)" } else { "" };
        let (kind, message) = match self.event {
            "AUE_login" if self.failed => ("failed_login", format!("failed login by {who} on {}", self.terminal())),
            "AUE_login" => ("login", format!("login by {who} on {}", self.terminal())),
            "AUE_logout" => ("logout", format!("logout of {who} on {}", self.terminal())),
            "AUE_openssh" => {
                let detail = first(&self.text);
                let detail = if detail.is_empty() { "login".to_string() } else { detail };
                (if self.failed { "failed_login" } else { "login" }, format!("ssh: {detail} ({who})"))
            }
            "AUE_su" => ("su", format!("su by {who}{outcome}: {}", first(&self.text))),
            "AUE_sudo" => ("sudo_command", format!("sudo by {who}{outcome}: {}", command())),
            "AUE_auth_user" | "AUE_ssauthorize" | "AUE_ssauthint" | "AUE_ssauthattempt" | "AUE_authenticate" => (
                if self.failed { "failed_login" } else { "login" },
                format!("authentication by {who}{outcome}: {}", first(&self.text)),
            ),
            "AUE_EXECVE" | "AUE_EXECVEAT" | "AUE_FEXECVE" | "AUE_POSIX_SPAWN" | "AUE_MAC_EXECVE" => {
                ("executed", format!("{who} ran {}{outcome}", command()))
            }
            "AUE_modify_password"
            | "AUE_modify_user"
            | "AUE_modify_group"
            | "AUE_create_user"
            | "AUE_create_group"
            | "AUE_delete_user"
            | "AUE_delete_group"
            | "AUE_add_to_group"
            | "AUE_remove_from_group"
            | "AUE_enable_user"
            | "AUE_disable_user" => {
                ("account_changed", format!("{} by {who}{outcome}: {}", self.event, first(&self.text)))
            }
            _ => return None.into_iter(),
        };
        Some(Event::new(time, kind, message)).into_iter()
    }
}

impl Audit<'_> {
    fn terminal(&self) -> String {
        match (self.terminal_port, self.terminal_address.is_empty()) {
            (Some(port), false) if port != 0 => format!("{}:{port}", self.terminal_address),
            (_, false) => self.terminal_address.clone(),
            _ => "local".to_string(),
        }
    }
}

/// The time of a header: seconds and milliseconds. `None` when it does not fit a timestamp
/// (a damaged header), so a saturated date is never shown as recorded.
fn seconds(sec: u64, msec: u64) -> Option<Timestamp> {
    // The header holds milliseconds; a larger value is not a fraction of a second, so only
    // the whole seconds are kept then.
    let (millis, precision) = if msec < 1000 { (msec as u32, Precision::Millis) } else { (0, Precision::Seconds) };
    Timestamp::checked(i64::try_from(sec).ok()?, millis * 1_000_000, precision, Basis::Recorded)
}

/// One decoded subject or process token.
fn subject(r: &mut Reader, wide_port: bool, extended: bool, a: &mut Audit) -> Option<()> {
    a.audit_user_id = Some(r.u32()?);
    a.effective_user_id = Some(r.u32()?);
    a.effective_group_id = Some(r.u32()?);
    a.real_user_id = Some(r.u32()?);
    a.real_group_id = Some(r.u32()?);
    a.process_id = Some(r.u32()?);
    a.session_id = Some(r.u32()?);
    a.terminal_port = Some(if wide_port { r.u64()? } else { u64::from(r.u32()?) });
    let length = if extended { r.u32()? } else { 4 };
    a.terminal_address = r.address(length)?;
    Some(())
}

/// What went wrong in one record.
enum Problem {
    /// A token id this parser does not know (or whose layout it does not decode).
    Unknown(u8),
    /// A token that runs past the end of its record.
    Cut(&'static str),
}

/// The token version Solaris and illumos write in the header (OpenBSM writes 11).
const SOLARIS_VERSION: u8 = 2;
/// The largest `audit_event` file read from the evidence.
const MAX_EVENT_TABLE: usize = 4 << 20;

/// A header time whose second part is nanoseconds.
fn nanoseconds(sec: u64, nsec: u64) -> Option<Timestamp> {
    let sec = i64::try_from(sec).ok()?;
    Timestamp::checked(sec, u32::try_from(nsec).ok().filter(|n| *n < 1_000_000_000)?, Precision::Nanos, Basis::Recorded)
}

fn decode<'a>(
    rec: &'a [u8],
    events: Option<&'a EventTable<'a>>,
) -> std::result::Result<(Audit<'a>, Option<Problem>), &'static str> {
    let mut r = Reader { data: rec, pos: 0 };
    let mut a = Audit { kind: "record", ..Audit::default() };
    let id = r.u8().ok_or("empty record")?;
    let record_bytes = r.u32().ok_or("short header")?;
    a.record_bytes = record_bytes;
    a.version = r.u8().ok_or("short header")?;
    let event = r.u16().ok_or("short header")?;
    a.event_modifier = r.u16().ok_or("short header")?;
    let extended = matches!(id, AUT_HEADER32_EX | AUT_HEADER64_EX);
    let wide = matches!(id, AUT_HEADER64 | AUT_HEADER64_EX);
    if extended {
        let length = r.u32().ok_or("short header")?;
        a.machine = r.address(length).ok_or("bad header address")?;
    }
    let (sec, msec) = if wide {
        (r.u64().ok_or("short header")?, r.u64().ok_or("short header")?)
    } else {
        (u64::from(r.u32().ok_or("short header")?), u64::from(r.u32().ok_or("short header")?))
    };
    // Solaris and illumos (token version 2) store nanoseconds where OpenBSM stores milliseconds.
    a.time = if a.version == SOLARIS_VERSION { nanoseconds(sec, msec) } else { seconds(sec, msec) };
    a.event_id = u32::from(event);
    if let Some(info) = events.and_then(|t| t.get(&a.event_id)) {
        (a.event, a.event_description, a.event_classes) = (info.name, info.description, info.classes);
    }
    a.tokens.push("header");
    let mut problem = None;
    while r.pos < rec.len() {
        let Some(token) = r.u8() else { break };
        let outcome = token_body(token, &mut r, &mut a);
        match outcome {
            Some(true) => {}
            Some(false) => break, // the trailer
            None => {
                problem = Some(if is_known(token) { Problem::Cut(token_name(token)) } else { Problem::Unknown(token) });
                break;
            }
        }
    }
    Ok((a, problem))
}

fn is_known(token: u8) -> bool {
    token_name(token) != "unknown"
}

fn token_name(token: u8) -> &'static str {
    match token {
        AUT_TRAILER => "trailer",
        AUT_IPC => "ipc",
        AUT_PATH => "path",
        AUT_SUBJECT32 | AUT_SUBJECT64 => "subject",
        AUT_SUBJECT32_EX | AUT_SUBJECT64_EX => "subject_ex",
        AUT_PROCESS32 | AUT_PROCESS64 => "process",
        AUT_PROCESS32_EX | AUT_PROCESS64_EX => "process_ex",
        AUT_RETURN32 | AUT_RETURN64 => "return",
        AUT_TEXT => "text",
        AUT_OPAQUE => "opaque",
        AUT_IN_ADDR => "in_addr",
        AUT_IN_ADDR_EX => "in_addr_ex",
        AUT_IP => "ip",
        AUT_IPORT => "iport",
        AUT_ARG32 | AUT_ARG64 => "arg",
        AUT_SOCKET => "socket",
        AUT_SOCKET_EX => "socket_ex",
        AUT_SOCKINET32 | AUT_SOCKINET128 => "socket_inet",
        AUT_SOCKUNIX => "socket_unix",
        AUT_SEQ => "seq",
        AUT_ATTR | AUT_ATTR32 | AUT_ATTR64 => "attr",
        AUT_IPC_PERM => "ipc_perm",
        AUT_GROUPS | AUT_NEWGROUPS => "groups",
        AUT_EXEC_ARGS => "exec_args",
        AUT_EXEC_ENV => "exec_env",
        AUT_CMD => "cmd",
        AUT_EXIT => "exit",
        AUT_ZONENAME => "zonename",
        AUT_USER => "user",
        AUT_FMRI => "fmri",
        AUT_UPRIV => "use_of_privilege",
        AUT_UAUTH => "use_of_authorization",
        AUT_HOST => "host",
        AUT_OTHER_FILE32 | AUT_OTHER_FILE64 => "file",
        _ => "unknown",
    }
}

/// Decodes one token whose id was just read. `Some(true)` to continue, `Some(false)` at the
/// trailer, `None` when the token is unknown or runs past the record.
fn token_body<'a>(token: u8, r: &mut Reader<'a>, a: &mut Audit<'a>) -> Option<bool> {
    let name = token_name(token);
    if name == "unknown" {
        return None;
    }
    match token {
        AUT_TRAILER => {
            // The magic number and the length are checked by the caller against the record.
            r.skip(6)?;
            a.tokens.push("trailer");
            return Some(false);
        }
        AUT_PATH => {
            let text = r.counted()?;
            if a.paths.len() < MAX_ITEMS {
                a.paths.push(string(text));
            }
        }
        AUT_TEXT => {
            let text = r.counted()?;
            if a.text.len() < MAX_ITEMS {
                a.text.push(string(text));
            }
        }
        AUT_SUBJECT32 => subject(r, false, false, a)?,
        AUT_SUBJECT64 => subject(r, true, false, a)?,
        AUT_SUBJECT32_EX => subject(r, false, true, a)?,
        AUT_SUBJECT64_EX => subject(r, true, true, a)?,
        AUT_PROCESS32 | AUT_PROCESS64 | AUT_PROCESS32_EX | AUT_PROCESS64_EX => {
            // A process token describes another process (a signal's target): the ids are read
            // to keep the cursor right but the subject's own are not overwritten.
            let mut other = Audit::default();
            let wide = matches!(token, AUT_PROCESS64 | AUT_PROCESS64_EX);
            subject(r, wide, matches!(token, AUT_PROCESS32_EX | AUT_PROCESS64_EX), &mut other)?;
            if a.target_processes.len() < MAX_ITEMS {
                a.target_processes.push(format!(
                    "pid {} audit user {} uid {}",
                    other.process_id.unwrap_or(0),
                    other.audit_user_id.unwrap_or(0),
                    other.effective_user_id.unwrap_or(0)
                ));
            }
        }
        AUT_RETURN32 | AUT_RETURN64 => {
            let status = r.u8()?;
            let value = if token == AUT_RETURN64 { r.u64()? } else { u64::from(r.u32()?) };
            a.return_status = Some(status);
            a.return_value = Some(value);
            a.failed = status != 0;
            a.result = if status == 0 { "success" } else { "failure" };
        }
        AUT_ARG32 | AUT_ARG64 => {
            let number = r.u8()?;
            let value = if token == AUT_ARG64 { r.u64()? } else { u64::from(r.u32()?) };
            let label = r.counted()?;
            if a.arguments.len() < MAX_ITEMS {
                a.arguments.push(format!("{}={value:#x} (arg {number})", string(label)));
            }
        }
        AUT_EXEC_ARGS | AUT_EXEC_ENV => {
            let count = r.u32()?;
            let list = if token == AUT_EXEC_ARGS { &mut a.exec_args } else { &mut a.exec_env };
            // The count is not trusted as a loop bound: each string needs at least its NUL.
            for _ in 0..count {
                let rest = r.data.get(r.pos..)?;
                let end = memchr::memchr(0, rest)?;
                let text = r.bytes(end + 1)?;
                if list.len() < MAX_ITEMS {
                    list.push(string(&text[..end]));
                }
            }
        }
        AUT_ATTR | AUT_ATTR32 | AUT_ATTR64 => {
            let mode = r.u32()?;
            let user = r.u32()?;
            let group = r.u32()?;
            let _filesystem = r.u32()?;
            let node = r.u64()?;
            r.skip(if token == AUT_ATTR64 { 8 } else { 4 })?;
            if a.attribute_mode.is_none() {
                (a.attribute_mode, a.attribute_user_id, a.attribute_group_id, a.attribute_node_id) =
                    (Some(mode), Some(user), Some(group), Some(node));
            }
        }
        AUT_EXIT => {
            let status = r.u32()?;
            let value = r.u32()?;
            a.text.push(Cow::Owned(format!("exit status {status} value {value}")));
        }
        AUT_SEQ => a.sequence = Some(r.u32()?),
        AUT_ZONENAME => a.zone = string(r.counted()?).into_owned(),
        AUT_USER => {
            let id = r.u32()?;
            let name = string(r.counted()?);
            if a.users.len() < MAX_ITEMS {
                a.users.push(format!("{id} {name}"));
            }
        }
        AUT_UPRIV => {
            let used = r.u8()? != 0;
            let set = string(r.counted()?);
            if a.privileges.len() < MAX_ITEMS {
                a.privileges.push(if used { set.into_owned() } else { format!("{set} (failed)") });
            }
        }
        AUT_FMRI => {
            let name = r.counted()?;
            if a.services.len() < MAX_ITEMS {
                a.services.push(string(name));
            }
        }
        AUT_UAUTH => {
            let name = r.counted()?;
            if a.authorizations.len() < MAX_ITEMS {
                a.authorizations.push(string(name));
            }
        }
        AUT_HOST => a.socket.push(format!("host {}", r.address(4)?)),
        AUT_IN_ADDR => a.socket.push(format!("address {}", r.address(4)?)),
        AUT_IN_ADDR_EX => {
            let length = r.u32()?;
            a.socket.push(format!("address {}", r.address(length)?));
        }
        AUT_IPORT => a.socket.push(format!("port {}", r.u16()?)),
        AUT_IP => r.skip(20)?,
        AUT_SOCKET => {
            let kind = r.u16()?;
            let local_port = r.u16()?;
            let local = r.address(4)?;
            let remote_port = r.u16()?;
            let remote = r.address(4)?;
            a.socket.push(format!("type {kind} {local}:{local_port} -> {remote}:{remote_port}"));
        }
        AUT_SOCKET_EX => {
            let domain = r.u16()?;
            let kind = r.u16()?;
            let local_length = u32::from(r.u16()?);
            let local_port = r.u16()?;
            let local = r.address(local_length)?;
            let remote_length = u32::from(r.u16()?);
            let remote_port = r.u16()?;
            let remote = r.address(remote_length)?;
            a.socket.push(format!("domain {domain} type {kind} {local}:{local_port} -> {remote}:{remote_port}"));
        }
        AUT_SOCKINET32 | AUT_SOCKINET128 => {
            let family = r.u16()?;
            let port = r.u16()?;
            let address = r.address(if token == AUT_SOCKINET32 { 4 } else { 16 })?;
            a.socket.push(format!("family {family} {address}:{port}"));
        }
        AUT_SOCKUNIX => {
            // `family (2), path`, the path ending at its NUL (checked on real FreeBSD records:
            // `82 0001 "/var/run/log" 00`); the 104 bytes of `sun_path` are not all written.
            let family = r.u16()?;
            let rest = r.data.get(r.pos..)?;
            let end = memchr::memchr(0, rest)?;
            let path = r.bytes(end + 1)?;
            a.socket.push(format!("family {family} {}", string(&path[..end])));
        }
        AUT_GROUPS | AUT_NEWGROUPS => {
            let count = usize::from(r.u16()?);
            r.skip(count.checked_mul(4)?)?;
        }
        AUT_IPC => r.skip(5)?,
        AUT_IPC_PERM => r.skip(28)?,
        AUT_OPAQUE => {
            r.counted()?;
        }
        AUT_CMD => {
            for list in [&mut a.exec_args, &mut a.exec_env] {
                let count = r.u16()?;
                for _ in 0..count {
                    let text = r.counted()?;
                    if list.len() < MAX_ITEMS {
                        list.push(string(text));
                    }
                }
            }
        }
        // File tokens inside a record are not expected; the layout is skipped as a unit.
        AUT_OTHER_FILE32 | AUT_OTHER_FILE64 => return None,
        _ => return None,
    }
    // A record of megabytes of tiny tokens must not become megabytes of output per field.
    a.socket.truncate(MAX_ITEMS);
    a.text.truncate(MAX_ITEMS);
    a.target_processes.truncate(MAX_ITEMS);
    if a.tokens.len() < MAX_ITEMS {
        a.tokens.push(name);
    }
    Some(true)
}

// ---- the parser ----

fn is_file(id: u8) -> bool {
    matches!(id, AUT_OTHER_FILE32 | AUT_OTHER_FILE64)
}

/// Finds the next position at or after `from` where a plausible record starts: a header id,
/// a length that fits the file, and a trailer magic where the record would end.
fn resync(data: &[u8], from: usize) -> Option<usize> {
    let mut at = from;
    while at < data.len() {
        let next = at + memchr::memchr2(AUT_HEADER32, AUT_HEADER64, data.get(at..)?)?;
        let ok = (|| -> Option<bool> {
            let length = u32::from_be_bytes(data.get(next + 1..next + 5)?.try_into().ok()?) as usize;
            let end = next.checked_add(length)?;
            if !(MIN_RECORD..=MAX_RECORD).contains(&length) {
                return Some(false);
            }
            // Solaris and illumos records have no trailer: the next record must start where
            // this one ends.
            if data.get(next + 5)? == &SOLARIS_VERSION {
                return Some(end == data.len() || data.get(end).is_some_and(|&b| is_header(b) || is_file(b)));
            }
            Some(
                data.get(end.checked_sub(7)?)? == &AUT_TRAILER
                    && data.get(end - 6..end - 4)? == TRAILER_MAGIC.to_be_bytes(),
            )
        })()
        .unwrap_or(false);
        if ok {
            return Some(next);
        }
        at = next + 1;
    }
    None
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    if !(is_header(data[0]) || matches!(data[0], AUT_OTHER_FILE32 | AUT_OTHER_FILE64)) {
        return Err(Error::format("not a BSM audit trail (no header or file token at the start)"));
    }
    // The host's own table when it was collected: it is exact for that release.
    let own_text = ["etc/security/audit_event", "private/etc/security/audit_event"]
        .iter()
        .find_map(|path| input.host.read_text(path))
        .filter(|text| text.len() <= MAX_EVENT_TABLE);
    let own = own_text.as_deref().map(table).filter(|t| !t.is_empty());
    let table = own.as_ref().or_else(|| events_for(input.host.os));
    if table.is_none() {
        sink.warn("no audit_event table for this operating system: events are shown by number only");
    }
    let mut unknown: BTreeMap<u8, u64> = BTreeMap::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let id = data[pos];
        if is_file(id) {
            let mut r = Reader { data, pos: pos + 1 };
            let times = (|| {
                let wide = id == AUT_OTHER_FILE64;
                let (sec, usec) = if wide { (r.u64()?, r.u64()?) } else { (u64::from(r.u32()?), u64::from(r.u32()?)) };
                Some((sec, usec, r.counted()?))
            })();
            let Some((sec, usec, name)) = times else {
                sink.warn(format!("offset {pos}: file token is cut"));
                break;
            };
            // Microseconds here, unlike the header's milliseconds.
            let time = i64::try_from(sec).ok().and_then(|sec| {
                Timestamp::checked(sec, usec.min(999_999) as u32 * 1000, Precision::Micros, Basis::Recorded)
            });
            sink.emit(
                Loc::Offset(pos as u64),
                &Audit { time, kind: "file", paths: vec![string(name)], tokens: vec!["file"], ..Audit::default() },
            )?;
            pos = r.pos;
            continue;
        }
        let length = data.get(pos + 1..pos + 5).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize);
        let valid = is_header(id) && length.is_some_and(|l| (MIN_RECORD..=MAX_RECORD).contains(&l));
        let Some(length) = length.filter(|_| valid) else {
            sink.warn(format!("offset {pos}: not a record header (byte {id:#04x}); looking for the next one"));
            match resync(data, pos + 1) {
                Some(next) => {
                    pos = next;
                    continue;
                }
                None => break,
            }
        };
        let Some(rec) = data.get(pos..pos + length) else {
            sink.warn(format!(
                "offset {pos}: record of {length} bytes is cut (only {} present); stopping",
                data.len() - pos
            ));
            break;
        };
        match decode(rec, table) {
            Ok((audit, problem)) => {
                match problem {
                    Some(Problem::Unknown(token)) => *unknown.entry(token).or_default() += 1,
                    Some(Problem::Cut(name)) => sink.warn(format!("offset {pos}: {name} token runs past the record")),
                    None => {
                        // The trailer repeats the record length: a mismatch is a damaged record.
                        let count =
                            rec.get(length - 4..).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize);
                        // Solaris and illumos records have no trailer: the header length ends them.
                        let solaris = audit.version == SOLARIS_VERSION;
                        if !solaris && (count != Some(length) || rec.get(length - 7) != Some(&AUT_TRAILER)) {
                            sink.warn(format!("offset {pos}: record has no valid trailer"));
                        }
                    }
                }
                if audit.time.is_none() {
                    sink.warn(format!("offset {pos}: the time in the header is out of range"));
                }
                sink.emit(Loc::Offset(pos as u64), &audit)?;
            }
            Err(why) => sink.warn(format!("offset {pos}: {why}")),
        }
        pos += length;
    }
    for (token, count) in unknown {
        sink.warn(format!(
            "token id {token:#04x} is not understood ({count} records): each such record was kept up to that token and the rest of it skipped"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    const FREEBSD_FILES: [(&str, &[u8]); 1] = [("etc/freebsd-update.conf", b"x")];

    fn on_freebsd(data: &[u8]) -> String {
        let path = "var/audit/20231114221320.20231114221400";
        run_on_host(&ARTIFACT, &[FREEBSD_FILES[0], (path, data)], path, 0)
    }

    #[test]
    fn reads_a_real_freebsd_trail() {
        insta::assert_snapshot!(on_freebsd(&fixture("bsm-audit/freebsd.audit")));
    }

    /// The first record of the real trail, field by field, from `praudit -l` of the same file
    /// (`header,97,11,su(1),0,Fri Nov 13 01:38:57 2026, + 133 msec,subject,-1,root,wheel,root,
    /// wheel,1155,1155,0,0.0.0.0,text,successful authentication,return,success,0,trailer,97`).
    #[test]
    fn matches_the_praudit_values_of_the_first_record() {
        let out = on_freebsd(&fixture("bsm-audit/freebsd.audit"));
        let first = out.lines().next().unwrap_or_default();
        for expected in [
            "\"event_id\":6159",
            "\"event\":\"AUE_su\"",
            "\"event_description\":\"su(1)\"",
            "\"version\":11",
            "\"record_bytes\":97",
            "\"audit_user_id\":4294967295,\"effective_user_id\":0,\"effective_group_id\":0,\"real_user_id\":0,\"real_group_id\":0",
            "\"process_id\":1155,\"session_id\":1155,\"terminal_port\":0,\"terminal_address\":\"0.0.0.0\"",
            "\"text\":[\"successful authentication\"]",
            "\"result\":\"success\"",
            "\"time\":\"2026-11-13T01:38:57.133Z\"",
        ] {
            assert!(first.contains(expected), "{expected} not in {first}");
        }
    }

    /// A record of the real trail (`connect(2)` of a process to the syslog socket): the unix socket
    /// token holds the path up to its NUL, not a fixed field. `praudit -l` of it:
    /// `header,111,11,connect(2),0,Fri Nov 13 01:41:06 2026, + 142 msec,argument,1,0x4,fd,
    /// socket-unix,1,/var/run/log,path,/var/run/log,subject,alice,root,alice,alice,alice,923,919,
    /// 24986,127.0.0.1,return,success,0,trailer,111`.
    #[test]
    fn a_real_unix_socket_token() {
        let hex = "140000006f0b002000006af66ab20000008e2d010000000400036664008200012f7661722f72756e2f6c6f670023000d2f7661722f72756e2f6c6f670024000003ea00000000000003ea000003ea000003ea0000039b000003970000619a7f00000127000000000013b1050000006f";
        let data: Vec<u8> =
            (0..hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok()).collect();
        let out = on_freebsd(&data);
        assert!(out.contains("\"event\":\"AUE_CONNECT\""), "{out}");
        assert!(out.contains("\"socket\":[\"family 1 /var/run/log\"]"), "{out}");
        assert!(out.contains("\"paths\":[\"/var/run/log\"]"));
        assert!(out.contains("\"audit_user_id\":1002,\"effective_user_id\":0,\"effective_group_id\":1002"));
        assert!(out.contains(
            "\"process_id\":923,\"session_id\":919,\"terminal_port\":24986,\"terminal_address\":\"127.0.0.1\""
        ));
        assert!(!out.contains("--- warning"), "{out}");
    }

    #[test]
    fn macos_numbers_use_the_macos_table() {
        let data = fixture("bsm-audit/macos-synthetic.audit");
        let mac = run(&ARTIFACT, "private/var/audit/20231114221320.20231114221400", &data, 0);
        insta::assert_snapshot!("macos", mac);
        // The same bytes on a FreeBSD host name event 43201 differently.
        let freebsd = on_freebsd(&data);
        assert!(mac.contains("AUE_GETATTRLISTBULK") && !mac.contains("AUE_WAIT6"));
        assert!(freebsd.contains("AUE_WAIT6") && !freebsd.contains("AUE_GETATTRLISTBULK"));
    }

    #[test]
    fn a_host_without_a_table_shows_numbers_and_says_so_once() {
        let out = run(&ARTIFACT, "var/audit/x", &fixture("bsm-audit/macos-synthetic.audit"), 0);
        assert_eq!(out.matches("no audit_event table").count(), 1, "{out}");
        assert!(out.contains("\"event_id\":45028,\"event\":\"\""));
    }

    #[test]
    fn the_other_token_layouts() {
        insta::assert_snapshot!(on_freebsd(&fixture("bsm-audit/tokens-synthetic.audit")));
    }

    #[test]
    fn unknown_tokens_end_the_record_with_one_warning_and_the_next_record_is_read() {
        let mut data = fixture("bsm-audit/macos-synthetic.audit");
        // Overwrite the first token after the first record's header with an unknown id.
        let at = 1 + 4 + 1 + 2 + 2 + 4 + 4 + 4 + 4; // header32_ex with an IPv4 machine address
        data[at] = 0xEE;
        let out = on_freebsd(&data);
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 5, "{out}");
        assert_eq!(out.matches("--- warning").count(), 1, "{out}");
        assert!(out.contains("token id 0xee is not understood (1 records)"), "{out}");
        assert!(out.contains("\"event_id\":45028"));
    }

    #[test]
    fn garbage_between_records_is_skipped_to_the_next_header() {
        let data = fixture("bsm-audit/macos-synthetic.audit");
        let first = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        let mut damaged = data[..first].to_vec();
        damaged.extend_from_slice(b"\x00\x01garbage\x02");
        damaged.extend_from_slice(&data[first..]);
        let out = on_freebsd(&damaged);
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 5, "{out}");
        assert_eq!(out.matches("--- warning").count(), 1, "{out}");
        assert!(out.contains("looking for the next one"));
    }

    #[test]
    fn a_cut_record_and_a_cut_trail() {
        let data = fixture("bsm-audit/macos-synthetic.audit");
        let out = on_freebsd(&data[..data.len() - 10]);
        assert!(out.contains("is cut (only"), "{out}");
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 4);
        assert!(on_freebsd(b"").contains("skipped: empty file"));
        assert!(on_freebsd(b"not an audit trail").contains("failed: not a BSM audit trail"));
    }

    #[test]
    fn execs_and_logins_become_timeline_events() {
        let out = on_freebsd(&fixture("bsm-audit/freebsd.audit"));
        let timeline = out.split("--- timeline ---").nth(1).unwrap_or_default();
        assert!(timeline.contains("executed") || timeline.contains("login") || timeline.contains("su"), "{timeline}");
    }

    /// A record of 300,000 three-byte tokens (and 300,000 exec arguments) must not become that many
    /// output items: every list is capped.
    #[test]
    fn a_record_of_many_tiny_tokens_is_capped() {
        let mut body = Vec::new();
        for _ in 0..300_000 {
            body.extend([AUT_IPORT, 0, 80]);
        }
        body.push(AUT_EXEC_ARGS);
        body.extend(300_000u32.to_be_bytes());
        body.extend(std::iter::repeat_n(0u8, 300_000));
        let total = 18 + body.len() + 7;
        let mut data = vec![AUT_HEADER32];
        data.extend((total as u32).to_be_bytes());
        data.extend([11, 0, 23, 0, 0]);
        data.extend(1_700_000_000u32.to_be_bytes());
        data.extend(5u32.to_be_bytes());
        data.extend(body);
        data.push(AUT_TRAILER);
        data.extend(TRAILER_MAGIC.to_be_bytes());
        data.extend((total as u32).to_be_bytes());
        let out = on_freebsd(&data);
        let record = out.lines().next().unwrap_or_default();
        assert!(record.starts_with('{') && record.len() < 200_000, "{} bytes", record.len());
        assert_eq!(record.matches("port 80").count(), MAX_ITEMS);
        assert!(!out.contains("--- warning"), "{}", &out[out.len().saturating_sub(300)..]);
    }

    /// Solaris and illumos: token version 2, nanoseconds in the header, no trailer token, and
    /// event numbers that only the host's own `audit_event` file names.
    #[test]
    fn solaris_records_use_nanoseconds_no_trailer_and_the_hosts_event_table() {
        let mut rec = vec![0x14u8];
        rec.extend_from_slice(&30u32.to_be_bytes());
        rec.push(2);
        rec.extend_from_slice(&6159u16.to_be_bytes());
        rec.extend_from_slice(&0u16.to_be_bytes());
        rec.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        rec.extend_from_slice(&123_456_789u32.to_be_bytes());
        rec.extend_from_slice(&[0x28, 0, 3, b'h', b'i', 0]);
        rec.extend_from_slice(&[0x27, 0, 0, 0, 0, 0]);
        assert_eq!(rec.len(), 30);
        let files: [(&str, &[u8]); 2] =
            [("var/audit/trail", &rec), ("etc/security/audit_event", b"6159:AUE_su:su:lo\n")];
        let out = run_on_host(&ARTIFACT, &files, "var/audit/trail", 0);
        assert!(!out.contains("warning"), "{out}");
        assert!(out.contains(r#""time":"2023-11-14T22:13:20.123456789Z""#), "{out}");
        assert!(out.contains(r#""event_id":6159,"event":"AUE_su""#), "{out}");
    }

    #[test]
    fn solaris_records_are_found_again_after_garbage() {
        let mut rec = vec![0x14u8];
        rec.extend_from_slice(&30u32.to_be_bytes());
        rec.push(2);
        rec.extend_from_slice(&[0, 1, 0, 0]);
        rec.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        rec.extend_from_slice(&0u32.to_be_bytes());
        rec.extend_from_slice(&[0x28, 0, 3, b'h', b'i', 0, 0x27, 0, 0, 0, 0, 0]);
        let data = [&rec, b"\xff\xfe junk".as_slice(), &rec, &rec].concat();
        let out = run(&ARTIFACT, "var/audit/trail", &data, 0);
        assert_eq!(out.matches(r#""version":2"#).count(), 3, "{out}");
    }

    #[test]
    fn solaris_user_privilege_and_authorization_tokens() {
        let body: &[u8] = &[
            0x36, 0, 0, 0, 104, 0, 4, b'b', b'o', b'b', 0, // user 104 bob
            0x39, 1, 0, 4, b's', b'y', b's', 0, // privilege used
            0x39, 0, 0, 4, b'n', b'e', b't', 0, // privilege refused
            0x3f, 0, 4, b'a', b'.', b'b', 0, // authorization
            0x20, 0, 5, b's', b'v', b'c', b':', 0, // service
            0x27, 0, 0, 0, 0, 0,
        ];
        let mut rec = vec![0x14u8];
        rec.extend_from_slice(&(18 + body.len() as u32).to_be_bytes());
        rec.push(2);
        rec.extend_from_slice(&[0, 1, 0, 0]);
        rec.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        rec.extend_from_slice(&0u32.to_be_bytes());
        rec.extend_from_slice(body);
        let out = run(&ARTIFACT, "var/audit/trail", &rec, 0);
        assert!(!out.contains("not understood"), "{out}");
        assert!(out.contains(r#""users":["104 bob"]"#), "{out}");
        assert!(out.contains(r#""privileges":["sys","net (failed)"]"#), "{out}");
        assert!(out.contains(r#""authorizations":["a.b"],"services":["svc:"]"#), "{out}");
        assert!(out.contains(r#""result":"success""#), "{out}");
    }

    #[test]
    fn truncated_and_corrupted_input_never_panics() {
        for name in ["bsm-audit/freebsd.audit", "bsm-audit/macos-synthetic.audit", "bsm-audit/tokens-synthetic.audit"] {
            let data = fixture(name);
            for len in 0..data.len() {
                on_freebsd(&data[..len]);
            }
            for i in 0..data.len() {
                for mask in [0xff, 0x80, 0x01] {
                    let mut flipped = data.clone();
                    flipped[i] ^= mask;
                    on_freebsd(&flipped);
                }
            }
        }
    }
}
