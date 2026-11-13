//! ESXi's text logs: the VMkernel, VOB events, the VMware daemons (`hostd`, `vpxa`,
//! `rhttpproxy`...), the shell, authentication, syslog and per-VM logs. Line headers:
//! [`super::line`]. File locations: the live logs are in `/var/run/log` and `/var/log` holds the
//! persistent copy (the `vm-support` bundle and the UAC `esxi` profile read for this module keep both:
//! UAC's `artifacts/files/logs/var_log.yaml` and `var_run_log.yaml`); rotations are `name.0.gz`,
//! `name.1.gz`... VMware's own "Location of ESXi log files" article could not be retrieved while
//! writing this, so the locations come from those collections and the public samples.
//!
//! Events are written only where a line states something unambiguously. Message texts were
//! checked against public ESXi 6.7 and 8.0 logs (listed in `docs/LIMITATIONS.md`); the ones
//! that were not seen in a real log are named there as synthetic only.

use super::frag;
use super::line::{header, structured};
use crate::common::syslog::timeline_message;
use crate::linux::auth_log::classify;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, ESXI};
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

/// Paths of one log in both places ESXi keeps it, with rotations and `vm-support` pieces.
macro_rules! log_paths {
    ($($name:literal),+ $(,)?) => {
        &[$(concat!("var/run/log/", $name, ".*"), concat!("var/log/", $name, ".*")),+]
    };
}

pub const VMKERNEL: Artifact = Artifact::new(
    "esxi-vmkernel",
    "ESXi VMkernel log (vmkernel.log, vmkwarning.log)",
    Category::Logs,
    ESXI,
    log_paths!["vmkernel", "vmkwarning"],
    kernel,
)
.split_lines();

pub const VOB: Artifact = Artifact::new(
    "esxi-vob",
    "ESXi VOB events (vobd.log): logins, lockouts, ssh and shell switches, storage, network",
    Category::Logs,
    ESXI,
    log_paths!["vobd"],
    vob,
)
.split_lines();

pub const HOSTD: Artifact = Artifact::new(
    "esxi-hostd",
    "ESXi host agent log (hostd.log): logins, VM power operations, tasks",
    Category::Logs,
    ESXI,
    log_paths!["hostd"],
    hostd,
)
.split_lines();

pub const DAEMON_LOG: Artifact = Artifact::new(
    "esxi-daemon-log",
    "ESXi VMware daemon logs (vpxa, fdm, hostd-probe, rhttpproxy, vsansystem)",
    Category::Logs,
    ESXI,
    log_paths!["vpxa", "fdm", "hostd-probe", "rhttpproxy", "vsansystem", "vvold"],
    daemon,
)
.split_lines();

pub const SYSLOG: Artifact = Artifact::new(
    "esxi-syslog",
    "ESXi system logs (syslog.log, vmksummary.log, esxupdate.log, vmauthd.log, usb.log, lifecycle.log...)",
    Category::Logs,
    ESXI,
    log_paths![
        "syslog",
        "vmksummary",
        "esxupdate",
        "esxcli",
        "vmauthd",
        "usb",
        "lifecycle",
        "dhclient",
        "vmkdevmgr",
        "vmkeventd",
        "nfcd",
        "storagerm",
        "swapobjd",
        "iofiltervpd",
        "loadESX",
        "hostprofiletrace",
        "init",
    ],
    syslog,
)
.split_lines();

pub const SHELL: Artifact = Artifact::new(
    "esxi-shell",
    "ESXi shell commands (shell.log): every command typed in the ESXi shell or over ssh",
    Category::Execution,
    ESXI,
    log_paths!["shell"],
    shell,
)
.split_lines();

pub const AUTH: Artifact = Artifact::new(
    "esxi-auth-log",
    "ESXi authentication log (auth.log): sshd and DCUI logins, sessions",
    Category::Logs,
    ESXI,
    log_paths!["auth"],
    auth,
)
.split_lines();

pub const VM_LOG: Artifact = Artifact::new(
    "esxi-vm-log",
    "Virtual machine logs inside datastores (vmware.log, vmware-N.log): power on and off",
    Category::Logs,
    ESXI,
    &["vmfs/volumes/*/*/vmware.log*", "vmfs/volumes/*/*/vmware-*.log*"],
    vm_log,
)
.split_lines();

pub const SYSBOOT: Artifact = Artifact::new(
    "esxi-sysboot",
    "ESXi boot stages (sysboot.log)",
    Category::System,
    ESXI,
    log_paths!["sysboot"],
    sysboot,
);

// Each artifact first repairs `vm-support` pieces (see `frag`).
fn kernel(input: &Input, sink: &mut Sink) -> Result<()> {
    frag::run(input, sink, parse_kernel)
}
fn vob(input: &Input, sink: &mut Sink) -> Result<()> {
    frag::run(input, sink, parse_vob)
}
fn hostd(input: &Input, sink: &mut Sink) -> Result<()> {
    frag::run(input, sink, |input, sink| parse_daemon(input, sink, true))
}
fn daemon(input: &Input, sink: &mut Sink) -> Result<()> {
    frag::run(input, sink, |input, sink| parse_daemon(input, sink, false))
}
fn syslog(input: &Input, sink: &mut Sink) -> Result<()> {
    frag::run(input, sink, parse_syslog)
}
fn shell(input: &Input, sink: &mut Sink) -> Result<()> {
    frag::run(input, sink, parse_shell)
}
fn auth(input: &Input, sink: &mut Sink) -> Result<()> {
    frag::run(input, sink, parse_auth)
}
fn vm_log(input: &Input, sink: &mut Sink) -> Result<()> {
    frag::run(input, sink, parse_vm_log)
}
fn sysboot(input: &Input, sink: &mut Sink) -> Result<()> {
    frag::run(input, sink, parse_sysboot)
}

/// The timeline text of a line: the program or component, then the message.
fn describe(who: &str, message: &str) -> String {
    timeline_message(who, message)
}

// ---------------------------------------------------------------- VMkernel

#[derive(Serialize)]
struct Kernel<'a> {
    time: Option<Timestamp>,
    time_basis: Option<Basis>,
    level: &'a str,
    /// Time since boot, in the `D:HH:MM:SS.mmm` form of the earliest vmkwarning lines, which
    /// have no wall-clock time.
    uptime: &'a str,
    cpu: Option<u32>,
    /// The id of the VMkernel world (thread of control) that wrote the line.
    world_id: Option<u64>,
    op_id: &'a str,
    subsystem: &'a str,
    message: &'a str,
}

impl Record for Kernel<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let warn = matches!(self.level, "warning" | "alert" | "critical" | "error");
        self.time.filter(|_| warn).map(|ts| Event::new(ts, "log", describe("", self.message))).into_iter()
    }
}

/// `0:00:00:05.344`: days, hours, minutes, seconds since boot.
fn is_uptime(word: &str) -> bool {
    let parts: Vec<&str> = word.split([':', '.']).collect();
    parts.len() == 5 && parts.iter().all(|p| !p.is_empty() && p.len() <= 9 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// `cpu23:2098417)` or `cpu23:2098417 opID=a1b2)` at the start of a VMkernel message.
fn cpu_prefix(body: &str) -> (Option<u32>, Option<u64>, &str, &str) {
    let none = (None, None, "", body);
    let Some(rest) = body.strip_prefix("cpu") else { return none };
    let Some(end) = rest.find(')').filter(|&e| e <= 64) else { return none };
    let (inside, after) = (&rest[..end], &rest[end + 1..]);
    let Some((cpu, world)) = inside.split_once(':') else { return none };
    let (world, op_id) = world.split_once(" opID=").unwrap_or((world, ""));
    match (cpu.parse::<u32>(), world.parse::<u64>()) {
        (Ok(cpu), Ok(world)) => (Some(cpu), Some(world), op_id, after),
        _ => none,
    }
}

fn parse_kernel(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() {
            return Ok(());
        }
        let h = header(input, &text);
        let mut body = h.message;
        let mut uptime = "";
        if h.time.is_none() {
            if let Some((word, rest)) = body.split_once(' ').filter(|(w, _)| is_uptime(w)) {
                (uptime, body) = (word, rest);
            }
        }
        let (cpu, world_id, op_id, body) = cpu_prefix(body);
        let (level, body) = if let Some(rest) = body.strip_prefix("WARNING: ") {
            ("warning", rest)
        } else if let Some(rest) = body.strip_prefix("ALERT: ") {
            ("alert", rest)
        } else {
            (h.level, body)
        };
        let subsystem =
            body.split_once(": ").map(|(s, _)| s).filter(|s| !s.is_empty() && s.len() <= 48 && !s.contains(' '));
        sink.emit(
            Loc::Offset(line.offset),
            &Kernel {
                time: h.time,
                time_basis: h.time.map(|t| t.basis),
                level,
                uptime,
                cpu,
                world_id,
                op_id,
                subsystem: subsystem.unwrap_or_default(),
                message: body,
            },
        )
    })
}

// ---------------------------------------------------------------- VOB

#[derive(Serialize)]
struct Vob<'a> {
    time: Option<Timestamp>,
    time_basis: Option<Basis>,
    /// The part of the system that raised it (`netCorrelator`, `UserLevelCorrelator`).
    correlator: &'a str,
    /// Microseconds since boot, as vobd prints them.
    uptime_us: Option<u64>,
    /// `esx.audit.host.boot`, `vob.user.ssh.enabled`: empty on vobd's own delivery notes.
    event_id: &'a str,
    message: &'a str,
}

/// The timeline kind of a VOB event. Every VOB is logged twice, once as `vob.*` and once as the
/// `esx.*` event hostd shows, so only the `esx.audit.*` and `esx.problem.*` form is a timeline
/// entry.
fn vob_kind(id: &str) -> Option<&'static str> {
    if let Some(audit) = id.strip_prefix("esx.audit.") {
        return Some(match audit {
            "host.boot" => "boot",
            a if a.starts_with("host.stop") => "shutdown",
            "account.locked" => "account_locked",
            a if a.contains("login") && (a.contains("fail") || a.contains("reject")) => "failed_login",
            "ssh.enabled" | "ssh.disabled" | "shell.enabled" | "shell.disabled" | "dcui.enabled" | "dcui.disabled" => {
                "service_changed"
            }
            _ => "audit",
        });
    }
    id.starts_with("esx.problem.").then_some("problem")
}

impl Record for Vob<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let kind = vob_kind(self.event_id);
        self.time.zip(kind).map(|(ts, kind)| Event::new(ts, kind, describe(self.event_id, self.message))).into_iter()
    }
}

/// `[corr] 22427618us: [id] text`, either part optional.
fn split_vob(body: &str) -> (&str, Option<u64>, &str, &str) {
    let (mut correlator, mut rest) = ("", body);
    if let Some(inner) = body.strip_prefix('[') {
        if let Some((corr, tail)) = inner.split_once("] ").filter(|(c, _)| c.len() <= 64) {
            (correlator, rest) = (corr, tail);
        }
    }
    let mut uptime = None;
    if let Some((word, tail)) = rest.split_once(' ') {
        if let Some(digits) = word.strip_suffix("us:") {
            uptime = digits.parse().ok();
            if uptime.is_some() {
                rest = tail;
            }
        }
    }
    let mut id = "";
    if let Some(inner) = rest.strip_prefix('[') {
        if let Some((candidate, tail)) = inner.split_once("] ") {
            if candidate.contains('.') && !candidate.contains(' ') && candidate.len() <= 96 {
                (id, rest) = (candidate, tail);
            }
        }
    }
    (correlator, uptime, id, rest)
}

fn parse_vob(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() {
            return Ok(());
        }
        let h = header(input, &text);
        let (correlator, uptime_us, event_id, message) = split_vob(h.message);
        sink.emit(
            Loc::Offset(line.offset),
            &Vob { time: h.time, time_basis: h.time.map(|t| t.basis), correlator, uptime_us, event_id, message },
        )
    })
}

// ---------------------------------------------------------------- hostd and the other daemons

#[derive(Serialize)]
struct Daemon<'a> {
    time: Option<Timestamp>,
    time_basis: Option<Basis>,
    level: &'a str,
    program: &'a str,
    pid: Option<u32>,
    /// The `sub=` of the `[Originator@6876 ...]` block: the part of the daemon that wrote it.
    component: &'a str,
    op_id: &'a str,
    /// The account of the session the line belongs to; for login and logout events, the account
    /// the event names.
    user: &'a str,
    session: &'a str,
    message: &'a str,
    /// What the line states, when it is an event the timeline shows: `login`, `logout`,
    /// `failed_login`, `account_locked`, `service_changed`, `vm_power_on`, `vm_power_off`,
    /// `vm_registered`, `vm_removed`, `vm_created`, `vm_snapshot`.
    event: &'static str,
    /// The number hostd gives the vSphere event (`Event 112 : ...`).
    event_number: Option<u64>,
    remote_address: &'a str,
    remote_port: Option<u16>,
    vm: &'a str,
}

impl Record for Daemon<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        if self.event.is_empty() {
            return None.into_iter();
        }
        let who = if self.user.is_empty() { "unknown user" } else { self.user };
        let from =
            if self.remote_address.is_empty() { String::new() } else { format!(" from {}", self.remote_address) };
        let text = match self.event {
            "login" => format!("{who} logged in to the host{from}"),
            "logout" => format!("{who} logged out of the host{from}"),
            "failed_login" => format!("failed login of {who}{from}"),
            _ => {
                // `Event 116 : Removed web01 on esx01 ...`: the number is in its own column.
                let body = self
                    .message
                    .strip_prefix("Event ")
                    .and_then(|r| r.split_once(" : "))
                    .map_or(self.message, |(_, b)| b);
                describe("", body)
            }
        };
        self.time.map(|ts| Event::new(ts, self.event, text)).into_iter()
    }
}

/// What a hostd vSphere event line says.
#[derive(Default)]
struct Classified<'a> {
    event: &'static str,
    number: Option<u64>,
    user: &'a str,
    address: &'a str,
    vm: &'a str,
}

/// `user@address`: the address is what follows the last `@`.
fn account_at(who: &str) -> (&str, &str) {
    who.rsplit_once('@').unwrap_or((who, ""))
}

/// The VM name in `NAME on [ ]HOST <sep> DATACENTER`; names may hold ` on ` and ` in `, so the
/// last of each is used.
fn vm_before_host<'a>(head: &'a str, sep: &str) -> &'a str {
    let head = head.rsplit_once(sep).map_or(head, |(h, _)| h);
    head.rsplit_once(" on ").map_or("", |(vm, _)| vm.trim())
}

fn classify_hostd(message: &str) -> Classified<'_> {
    // `Accepted password for user root from 192.0.2.7` is the plain-text twin of the event that
    // follows it; it supplies the account and address but is not a second timeline entry.
    for prefix in ["Accepted password for user ", "Rejected password for user "] {
        if let Some((user, address)) = message.strip_prefix(prefix).and_then(|r| r.split_once(" from ")) {
            return Classified { user, address: address.trim(), ..Classified::default() };
        }
    }
    let Some(rest) = message.strip_prefix("Event ") else { return Classified::default() };
    let Some((number, body)) = rest.split_once(" : ") else { return Classified::default() };
    let number = number.parse().ok();
    let mut out = Classified { number, ..Classified::default() };
    if let Some(rest) = body.strip_prefix("User ") {
        if let Some((who, _)) = rest.split_once(" logged in as ") {
            (out.user, out.address) = account_at(who);
            out.event = "login";
        } else if let Some((who, _)) = rest.split_once(" logged out (") {
            (out.user, out.address) = account_at(who);
            out.event = "logout";
        }
    } else if let Some(who) = body.strip_prefix("Cannot login ") {
        (out.user, out.address) = account_at(who.trim());
        out.event = "failed_login";
    } else if let Some(rest) = body.strip_prefix("Remote access for ESXi local user account '") {
        if let Some((user, _)) = rest.split_once("' has been locked") {
            out.user = user;
            out.event = "account_locked";
        }
    } else if body.starts_with("SSH access has been ") || body.starts_with("SSH for the host ") {
        out.event = "service_changed";
    } else if let Some(head) = body.strip_suffix(" is powered on") {
        (out.event, out.vm) = ("vm_power_on", vm_before_host(head, " in "));
    } else if let Some(head) = body.strip_suffix(" is powered off") {
        (out.event, out.vm) = ("vm_power_off", vm_before_host(head, " in "));
    } else if let Some(rest) = body.strip_prefix("Removed ") {
        (out.event, out.vm) = ("vm_removed", vm_before_host(rest, " from "));
    } else if let Some(rest) = body.strip_prefix("Registered ") {
        (out.event, out.vm) = ("vm_registered", vm_before_host(rest, " in "));
    } else if let Some(rest) = body.strip_prefix("Created virtual machine ") {
        (out.event, out.vm) = ("vm_created", vm_before_host(rest, " in "));
    } else if body.starts_with("Task: Create virtual machine snapshot") {
        out.event = "vm_snapshot";
    }
    out
}

/// The two `<TCP 'address : port'>` endpoints of an rhttpproxy `New proxy client` line; the
/// second is the client.
fn proxy_client(message: &str) -> Option<(&str, u16)> {
    let rest = message.strip_prefix("New proxy client ")?;
    let mut endpoints = rest.split("<TCP '").skip(1);
    let _local = endpoints.next()?;
    let remote = endpoints.next()?.split('\'').next()?;
    let (address, port) = remote.rsplit_once(" : ")?;
    Some((address, port.trim().parse().ok()?))
}

fn parse_daemon(input: &Input, sink: &mut Sink, hostd: bool) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() {
            return Ok(());
        }
        let h = header(input, &text);
        let (sd, message) = structured(h.message);
        let c = if hostd { classify_hostd(message) } else { Classified::default() };
        let (address, port) = proxy_client(message).map_or(("", None), |(a, p)| (a, Some(p)));
        sink.emit(
            Loc::Offset(line.offset),
            &Daemon {
                time: h.time,
                time_basis: h.time.map(|t| t.basis),
                level: h.level,
                program: h.program,
                pid: h.pid,
                component: sd.component,
                op_id: sd.op_id,
                user: if c.user.is_empty() { sd.user } else { c.user },
                session: sd.session,
                message,
                event: c.event,
                event_number: c.number,
                remote_address: if c.address.is_empty() { address } else { c.address },
                remote_port: port,
                vm: c.vm,
            },
        )
    })
}

// ---------------------------------------------------------------- syslog family

#[derive(Serialize)]
struct Syslog<'a> {
    time: Option<Timestamp>,
    time_basis: Option<Basis>,
    level: &'a str,
    program: &'a str,
    pid: Option<u32>,
    message: &'a str,
    /// The timeline kind when the line states an event: `boot`, `shutdown`, `package_command`,
    /// `cron_executed`, `sftp_write`, `sftp_remove`.
    event: &'static str,
    /// The command, path or other object the event names.
    object: &'a str,
}

impl Record for Syslog<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let text = match self.event {
            "" => return None.into_iter(),
            "boot" => "host booted".to_string(),
            "shutdown" => "host shutting down".to_string(),
            "package_command" => format!("esxupdate ran {}", self.object),
            "cron_executed" => format!("cron ran {}", self.object),
            "sftp_write" => format!("sftp opened {} for writing", self.object),
            _ => format!("sftp removed {}", self.object),
        };
        self.time.map(|ts| Event::new(ts, self.event, text)).into_iter()
    }
}

/// `"path"` from the start of `text`: the quoted text and what follows.
fn quoted(text: &str) -> Option<(&str, &str)> {
    let rest = text.strip_prefix('"')?;
    // sftp-server does not escape quotes: the path ends at the last quote before the flags.
    let end = rest.rfind('"')?;
    Some((&rest[..end], &rest[end + 1..]))
}

fn classify_syslog<'a>(program: &str, message: &'a str) -> (&'static str, &'a str) {
    match program {
        "bootstop" if message.starts_with("Host has booted") => ("boot", ""),
        "bootstop" if message.starts_with("Host is powering off") || message.starts_with("Host is rebooting") => {
            ("shutdown", "")
        }
        "esxupdate" => match message.split_once("INFO: Command = ") {
            Some((_, command)) => ("package_command", command.trim()),
            None => ("", ""),
        },
        "crond" => match message.split_once(" cmd ") {
            Some((who, command)) if who.starts_with("USER ") => ("cron_executed", command.trim()),
            _ => ("", ""),
        },
        "sftp-server" => {
            if let Some((path, tail)) = message.strip_prefix("open ").and_then(quoted) {
                if tail
                    .trim_start()
                    .strip_prefix("flags ")
                    .is_some_and(|f| f.split(' ').next().is_some_and(|f| f.contains("WRITE")))
                {
                    return ("sftp_write", path);
                }
            }
            match message.strip_prefix("remove name ").and_then(quoted) {
                Some((path, _)) => ("sftp_remove", path),
                None => ("", ""),
            }
        }
        _ => ("", ""),
    }
}

fn parse_syslog(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() {
            return Ok(());
        }
        let h = header(input, &text);
        let (event, object) = classify_syslog(h.program, h.message);
        sink.emit(
            Loc::Offset(line.offset),
            &Syslog {
                time: h.time,
                time_basis: h.time.map(|t| t.basis),
                level: h.level,
                program: h.program,
                pid: h.pid,
                message: h.message,
                event,
                object,
            },
        )
    })
}

// ---------------------------------------------------------------- shell.log

#[derive(Serialize)]
struct Shell<'a> {
    time: Option<Timestamp>,
    time_basis: Option<Basis>,
    level: &'a str,
    /// `shell` for commands, `ESXShell` and `SSH` for the service switches.
    program: &'a str,
    pid: Option<u32>,
    /// The account named in `[root]: command`.
    user: &'a str,
    /// The command line, exactly as logged. A command typed over several lines is one record
    /// per line.
    command: &'a str,
    message: &'a str,
    /// `executed`, `shell_session`, `ssh_enabled`, `ssh_disabled`, `shell_enabled` or
    /// `shell_disabled`; empty for other lines.
    event: &'static str,
}

impl Record for Shell<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let text = match self.event {
            "" => return None.into_iter(),
            "executed" => format!("{} ran: {}", if self.user.is_empty() { "shell" } else { self.user }, self.command),
            _ => self.message.to_string(),
        };
        self.time.map(|ts| Event::new(ts, self.event, describe("", &text))).into_iter()
    }
}

fn parse_shell(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() {
            return Ok(());
        }
        let h = header(input, &text);
        let message = h.message.trim();
        let mut user = "";
        let mut command = "";
        let mut event = "";
        if let Some((who, rest)) =
            message.strip_prefix('[').and_then(|m| m.split_once("]: ")).filter(|(w, _)| w.len() <= 64)
        {
            (user, command) = (who, rest.trim());
            if !command.is_empty() {
                event = "executed";
            }
        } else {
            event = match message {
                "Interactive shell session started" => "shell_session",
                "SSH login enabled" => "ssh_enabled",
                "SSH login disabled" => "ssh_disabled",
                "ESXi shell login enabled" => "shell_enabled",
                "ESXi shell login disabled" => "shell_disabled",
                _ => "",
            };
        }
        sink.emit(
            Loc::Offset(line.offset),
            &Shell {
                time: h.time,
                time_basis: h.time.map(|t| t.basis),
                level: h.level,
                program: h.program,
                pid: h.pid,
                user,
                command,
                message,
                event,
            },
        )
    })
}

// ---------------------------------------------------------------- auth.log

#[derive(Serialize)]
struct AuthEntry<'a> {
    time: Option<Timestamp>,
    time_basis: Option<Basis>,
    level: &'a str,
    program: &'a str,
    pid: Option<u32>,
    message: &'a str,
    /// The classified event (`ssh_accepted`, `ssh_failed`, `auth_failure`, `session_opened`...),
    /// the same names as the Linux `auth-log` artifact; empty for other lines.
    event: &'static str,
    user: &'a str,
    remote_address: &'a str,
    remote_port: Option<u16>,
    method: &'a str,
    key_fingerprint: &'a str,
}

impl Record for AuthEntry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        if self.event.is_empty() {
            return None.into_iter();
        }
        let auth = crate::linux::auth_log::Auth {
            event: self.event,
            user: self.user,
            remote_address: self.remote_address,
            method: self.method,
            ..Default::default()
        };
        self.time.map(|ts| Event::new(ts, self.event, auth.describe(self.program, self.message))).into_iter()
    }
}

fn parse_auth(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() {
            return Ok(());
        }
        let h = header(input, &text);
        let a = classify(h.program, h.message).unwrap_or_default();
        sink.emit(
            Loc::Offset(line.offset),
            &AuthEntry {
                time: h.time,
                time_basis: h.time.map(|t| t.basis),
                level: h.level,
                program: h.program,
                pid: h.pid,
                message: h.message,
                event: a.event,
                user: a.user,
                remote_address: a.remote_address,
                remote_port: a.remote_port,
                method: a.method,
                key_fingerprint: a.key_fingerprint,
            },
        )
    })
}

// ---------------------------------------------------------------- vmware.log

#[derive(Serialize)]
struct VmLog<'a> {
    time: Option<Timestamp>,
    time_basis: Option<Basis>,
    /// The datastore folder name (`vmfs/volumes/<datastore>/<vm folder>/vmware.log`).
    datastore: &'a str,
    vm_folder: &'a str,
    /// The thread: `vmx`, `vcpu-0`, `mks`...
    thread: &'a str,
    /// `I` information, `W` warning, `E` error, `A` assertion or notice, followed by the line's
    /// serial number in the VMX's log; only the letter is kept.
    severity: &'a str,
    message: &'a str,
    /// `vm_power_on` or `vm_power_off`; empty otherwise.
    event: &'static str,
}

impl Record for VmLog<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let text = match self.event {
            "" => return None.into_iter(),
            "vm_power_on" => format!("{} powered on", self.vm_folder),
            _ => format!("{} powered off (VMX process exited)", self.vm_folder),
        };
        self.time.map(|ts| Event::new(ts, self.event, text)).into_iter()
    }
}

/// `2025-12-27T01:18:32.417Z| vmx| W115: PowerOn`: the time has no space after it, and the
/// pipes separate the thread from the level.
fn parse_vm_log(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut parts = input.path.split('/').skip(2);
    let (datastore, vm_folder) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() {
            return Ok(());
        }
        let parsed = nixcavate_core::time::parse_iso8601(text.as_bytes())
            .and_then(|(t, used)| Some((t, text.get(used..)?.strip_prefix("| ")?)));
        let (time, rest) = match parsed {
            Some((t, rest)) => {
                (Some(t.recorded().unwrap_or_else(|| input.local_time(t.secs, t.nanos, t.precision))), rest)
            }
            None => (None, &*text),
        };
        let (thread, after) = if time.is_some() { rest.split_once("| ").unwrap_or(("", rest)) } else { ("", rest) };
        let (severity, message) = match after.split_once(": ") {
            Some((code, msg)) if time.is_some() && is_level_code(code) => (&code[..1], msg),
            _ => ("", after),
        };
        let event = match (thread, message) {
            ("vmx", "PowerOn") => "vm_power_on",
            ("vmx", m) if m.starts_with("VMX has left the building") => "vm_power_off",
            _ => "",
        };
        sink.emit(
            Loc::Offset(line.offset),
            &VmLog { time, time_basis: time.map(|t| t.basis), datastore, vm_folder, thread, severity, message, event },
        )
    })
}

/// `I125`, `W115`, `A100`: a letter and the number of the line.
fn is_level_code(code: &str) -> bool {
    let mut chars = code.chars();
    chars.next().is_some_and(|c| c.is_ascii_uppercase())
        && !code[1..].is_empty()
        && code.len() <= 8
        && code[1..].bytes().all(|b| b.is_ascii_digit())
}

// ---------------------------------------------------------------- sysboot.log

#[derive(Serialize)]
struct Stage<'a> {
    /// The stage's start. The log writes local wall-clock time with no zone.
    start: Option<Timestamp>,
    end: Option<Timestamp>,
    stage: &'a str,
    /// Lines that are not a stage (`VMKernel Initialization Time: 15000000`).
    message: &'a str,
}

impl Record for Stage<'_> {}

/// `[2026-01-10 07:55:24.649244 - 2026-01-10 07:55:24.651093] sysboot: register-vmw-satp`.
fn parse_sysboot(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() {
            return Ok(());
        }
        let time = |s: &str| {
            nixcavate_core::time::parse_iso8601(s.trim().as_bytes())
                .map(|(t, _)| input.local_time(t.secs, t.nanos, t.precision))
        };
        let staged = text.strip_prefix('[').and_then(|r| r.split_once("] sysboot: ")).and_then(|(range, stage)| {
            let (start, end) = range.split_once(" - ")?;
            Some((time(start)?, time(end)?, stage.trim()))
        });
        match staged {
            Some((start, end, stage)) => {
                sink.emit(Loc::Line(line.number), &Stage { start: Some(start), end: Some(end), stage, message: "" })
            }
            None => sink.emit(Loc::Line(line.number), &Stage { start: None, end: None, stage: "", message: text }),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};
    use serde_json::Value;

    fn records(out: &str) -> Vec<Value> {
        out.lines().filter(|l| l.starts_with('{')).map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    #[test]
    fn vmkernel_lines_of_every_version() {
        let out = run(&VMKERNEL, "var/run/log/vmkernel.log", &fixture("esxi-logs/vmkernel.log"), 0);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn vob_events_become_timeline_entries_once() {
        let out = run(&VOB, "var/run/log/vobd.log", &fixture("esxi-logs/vobd.log"), 0);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn hostd_logins_vm_power_and_8_0_layout() {
        let out = run(&HOSTD, "var/run/log/hostd.log", &fixture("esxi-logs/hostd.log"), 0);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn rhttpproxy_gives_the_client_address() {
        let out = run(&DAEMON_LOG, "var/run/log/rhttpproxy.log", &fixture("esxi-logs/rhttpproxy.log"), 0);
        let rows = records(&out);
        let client = rows.iter().find(|r| r["remote_address"] == "203.0.113.20").expect("client row");
        assert_eq!(client["remote_port"], 51776);
        assert_eq!(client["component"], "Proxy Req 00544");
        assert!(!out.contains("--- timeline ---"), "{out}");
    }

    #[test]
    fn shell_commands_are_executed_events() {
        let out = run(&SHELL, "var/run/log/shell.log", &fixture("esxi-logs/shell.log"), 0);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn auth_log_uses_the_shared_classifier() {
        let out = run(&AUTH, "var/run/log/auth.log", &fixture("esxi-logs/auth.log"), 0);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn syslog_family_events() {
        let out = run(&SYSLOG, "var/run/log/syslog.log", &fixture("esxi-logs/syslog.log"), 0);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn vm_log_power_events_and_folder() {
        let out = run(&VM_LOG, "vmfs/volumes/ds1/web01/vmware.log", &fixture("esxi-logs/vmware.log"), 0);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn sysboot_stages() {
        let out = run(&SYSBOOT, "var/log/sysboot.log", &fixture("esxi-logs/sysboot.log"), 0);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn vm_support_pieces_are_repaired() {
        let line1 = "2025-12-09T07:46:48.332Z info hostd[1] [Originator@6876 sub=Vimsvc.ha-eventmgr] Event 1 : User root@203.0.113.9 logged in as x\n";
        let line2 = "2025-12-09T07:47:00.000Z info hostd[1] [Originator@6876 sub=Vimsvc.ha-eventmgr] Event 2 : User root@203.0.113.9 logged out (login time: x)\n";
        let (a, b) = line1.split_at(40);
        let first = a.to_string();
        let second = format!("{b}{line2}");
        let files: [(&str, &[u8]); 2] = [
            ("var/run/log/hostd.log.FRAG-00000", first.as_bytes()),
            ("var/run/log/hostd.log.FRAG-00001", second.as_bytes()),
        ];
        let all = [
            run_on_host(&HOSTD, &files, "var/run/log/hostd.log.FRAG-00000", 0),
            run_on_host(&HOSTD, &files, "var/run/log/hostd.log.FRAG-00001", 0),
        ]
        .concat();
        let rows = records(&all);
        let events: Vec<&str> = rows.iter().map(|r| r["event"].as_str().unwrap()).collect();
        assert_eq!(events, ["login", "logout"], "{all}");
        assert_eq!(rows[0]["event_number"], 1);
    }

    #[test]
    fn empty_truncated_and_garbage_input_do_not_panic() {
        let cases: [(&Artifact, &str, &str); 9] = [
            (&VMKERNEL, "var/run/log/vmkernel.log", "esxi-logs/vmkernel.log"),
            (&VOB, "var/run/log/vobd.log", "esxi-logs/vobd.log"),
            (&HOSTD, "var/run/log/hostd.log", "esxi-logs/hostd.log"),
            (&SYSLOG, "var/run/log/syslog.log", "esxi-logs/syslog.log"),
            (&SHELL, "var/run/log/shell.log", "esxi-logs/shell.log"),
            (&AUTH, "var/run/log/auth.log", "esxi-logs/auth.log"),
            (&VM_LOG, "vmfs/volumes/d/v/vmware.log", "esxi-logs/vmware.log"),
            (&SYSBOOT, "var/log/sysboot.log", "esxi-logs/sysboot.log"),
            (&DAEMON_LOG, "var/run/log/rhttpproxy.log", "esxi-logs/rhttpproxy.log"),
        ];
        for (artifact, path, name) in cases {
            let data = fixture(name);
            assert_eq!(run(artifact, path, b"", 0), "", "{}", artifact.id);
            run(artifact, path, b"\xff\xfe\0\0 \n\x80", 0);
            for n in 0..=data.len() {
                run(artifact, path, &data[..n], 0);
            }
            for i in (0..data.len()).step_by(11) {
                let mut flipped = data.clone();
                flipped[i] ^= 0xff;
                run(artifact, path, &flipped, 0);
            }
        }
    }
}
