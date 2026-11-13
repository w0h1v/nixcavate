//! UAC `live_response/` and CatScale command output: `ps`, `netstat`/`ss`, `lsof` and `lsmod`.
//!
//! UAC stores each command's output in a file named after the command line
//! (`ps_auxwww.txt`, `netstat_-lpeanut.txt`, `ss_-tanp.txt`, `lsof_-nPl.txt`, `lsmod.txt`)
//! next to `[root]/`. CatScale names them `<host>-<date>-<time>-<command>.txt` in its section
//! folders (`Process_and_Network/`, `System_Info/`), which the source puts next to `[root]/`
//! too. Layouts are read from each file's header line, because the same
//! command differs between procps, net-tools and iproute2 versions. References: ps(1),
//! netstat(8), ss(8), lsof(8), lsmod(8).

use crate::text::for_each_line;
use crate::text::lossy;
use crate::{Artifact, Category, Input, ANY_OS, LINUX};
use nixcavate_core::{Error, Loc, Record, Result, Sink};
use serde::Serialize;
use std::borrow::Cow;

pub const PROCESSES: Artifact = Artifact::new(
    "live-processes",
    "Process list captured by UAC or CatScale (ps)",
    Category::Live,
    ANY_OS,
    &[
        "../live_response/process/ps_auxwww.txt",
        "../live_response/process/ps_-ef.txt",
        "../live_response/process/ps_-eo_user_pid_ppid_pcpu_pmem_tty_stat_lstart_args.txt",
        "../live_response/process/ps_-eo_user_pid_ppid_pcpu_pmem_tty_stat_etime_args.txt",
        "../Process_and_Network/*-processes-axwwSo.txt",
    ],
    parse_processes,
);

pub const NETWORK: Artifact = Artifact::new(
    "live-network",
    "Sockets captured by UAC or CatScale (netstat, ss)",
    Category::Live,
    LINUX,
    &[
        "../live_response/network/netstat_-lpeanut.txt",
        "../live_response/network/netstat_-anp.txt",
        "../live_response/network/netstat_-an.txt",
        "../live_response/network/netstat_-a.txt",
        "../live_response/network/ss_-anp.txt",
        "../live_response/network/ss_-ap.txt",
        "../live_response/network/ss_-tanp.txt",
        "../live_response/network/ss_-tap.txt",
        "../live_response/network/ss_-tlnp.txt",
        "../live_response/network/ss_-tlp.txt",
        "../live_response/network/ss_-uanp.txt",
        "../live_response/network/ss_-uap.txt",
        "../live_response/network/ss_-ulnp.txt",
        "../live_response/network/ss_-ulp.txt",
        "../Process_and_Network/*-ss-anepo.txt",
        "../Process_and_Network/*-netstat-antup.txt",
        "../Process_and_Network/*-netstat-an.txt",
        "../Process_and_Network/*-netstat-pvWanoee.txt",
        "../Process_and_Network/*-netstat-pvTanoee.txt",
    ],
    parse_network,
);

// Not split: the header gives the column layout (TID/TASKCMD present or not).
pub const OPEN_FILES: Artifact = Artifact::new(
    "live-open-files",
    "Open files captured by UAC or CatScale (lsof)",
    Category::Live,
    ANY_OS,
    &[
        "../live_response/process/lsof_-nPl.txt",
        "../live_response/network/lsof_-nPli.txt",
        "../live_response/network/lsof_-U.txt",
        "../Process_and_Network/*-lsof-list-open-files.txt",
    ],
    parse_open_files,
);

pub const MODULES: Artifact = Artifact::new(
    "live-modules",
    "Loaded kernel modules captured by UAC or CatScale (lsmod)",
    Category::Live,
    LINUX,
    &["../live_response/system/lsmod.txt", "../System_Info/*-lsmod.txt"],
    parse_modules,
);

/// Splits the next whitespace-delimited word off `rest`.
fn word<'a>(rest: &mut &'a str) -> Option<&'a str> {
    let text = rest.trim_start();
    let end = text.find(char::is_whitespace).unwrap_or(text.len());
    *rest = &text[end..];
    (end > 0).then(|| &text[..end])
}

/// AIX's `ps` prints a start time older than a day as `Mar 10`, two words. Other layouts keep `default`.
fn started_word_count(rest: &str, default: usize) -> usize {
    let mut peek = rest;
    let (first, second) = (word(&mut peek), word(&mut peek));
    let month = first.is_some_and(|w| {
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].contains(&w)
    });
    if default == 1 && month && second.is_some_and(|w| w.len() <= 2 && w.bytes().all(|b| b.is_ascii_digit())) {
        2
    } else {
        default
    }
}

/// The next `count` words as one slice of the input, with the spacing between them as written.
fn words<'a>(rest: &mut &'a str, count: usize) -> Option<&'a str> {
    let text = rest.trim_start();
    let mut tail = text;
    for _ in 0..count {
        word(&mut tail)?;
    }
    *rest = tail;
    Some(&text[..text.len() - tail.len()])
}

// ---------------------------------------------------------------- ps

#[derive(Clone, Copy, PartialEq)]
enum Column {
    User,
    Pid,
    Ppid,
    Cpu,
    Mem,
    Tty,
    State,
    Started,
    Time,
    Elapsed,
    Other,
}

struct PsLayout {
    columns: Vec<Column>,
    /// `lstart` prints `Wed Nov 11 19:41:09 2026`: five words in one column.
    started_words: usize,
}

impl PsLayout {
    /// The columns before the command, from the header. The command is always last.
    fn from_header(header: &str) -> Option<Self> {
        let names: Vec<&str> = header.split_whitespace().collect();
        let (last, names) = names.split_last()?;
        if !matches!(*last, "COMMAND" | "CMD" | "ARGS") {
            return None;
        }
        let columns: Vec<Column> = names
            .iter()
            .map(|name| match *name {
                "USER" | "UID" => Column::User,
                "PID" => Column::Pid,
                "PPID" => Column::Ppid,
                "%CPU" | "PCPU" => Column::Cpu,
                "%MEM" | "PMEM" => Column::Mem,
                "TTY" | "TT" => Column::Tty,
                "STAT" | "S" => Column::State,
                "START" | "STIME" | "STARTED" => Column::Started,
                "TIME" => Column::Time,
                "ELAPSED" | "ETIME" => Column::Elapsed,
                _ => Column::Other,
            })
            .collect();
        // Only `lstart` puts the start time directly before the command.
        let lstart = names.last() == Some(&"STARTED");
        columns.contains(&Column::Pid).then_some(Self { columns, started_words: if lstart { 5 } else { 1 } })
    }
}

#[derive(Serialize)]
struct Process<'a> {
    user: Option<&'a str>,
    pid: u32,
    ppid: Option<u32>,
    cpu_percent: Option<f32>,
    mem_percent: Option<f32>,
    tty: Option<&'a str>,
    state: Option<&'a str>,
    /// As written by ps: a time of day, a month and day, or a full date. It has no year or
    /// zone in most layouts, so it is not turned into a timestamp.
    started: Option<&'a str>,
    cpu_time: Option<&'a str>,
    /// Only the `etime` variant has it: time since start, `[[dd-]hh:]mm:ss`.
    elapsed: Option<&'a str>,
    command: &'a str,
}

impl Record for Process<'_> {}

fn parse_processes(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut layout: Option<PsLayout> = None;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() {
            return Ok(());
        }
        let Some(layout) = &layout else {
            layout = Some(PsLayout::from_header(&text).ok_or_else(|| Error::format("not a recognized ps header"))?);
            return Ok(());
        };
        let mut rest: &str = &text;
        let mut process = Process {
            user: None,
            pid: 0,
            ppid: None,
            cpu_percent: None,
            mem_percent: None,
            tty: None,
            state: None,
            started: None,
            cpu_time: None,
            elapsed: None,
            command: "",
        };
        let mut pid = None;
        for column in &layout.columns {
            let cell = if *column == Column::Started {
                let count = started_word_count(rest, layout.started_words);
                words(&mut rest, count)
            } else {
                word(&mut rest)
            };
            let Some(cell) = cell else {
                sink.warn(format!("line {}: too few columns", line.number));
                return Ok(());
            };
            match column {
                Column::User => process.user = Some(cell),
                Column::Pid => pid = cell.parse().ok(),
                Column::Ppid => process.ppid = cell.parse().ok(),
                Column::Cpu => process.cpu_percent = cell.parse().ok(),
                Column::Mem => process.mem_percent = cell.parse().ok(),
                Column::Tty => process.tty = Some(cell),
                Column::State => process.state = Some(cell),
                Column::Started => process.started = Some(cell),
                Column::Time => process.cpu_time = Some(cell),
                Column::Elapsed => process.elapsed = Some(cell),
                Column::Other => {}
            }
        }
        let Some(pid) = pid else {
            sink.warn(format!("line {}: invalid pid", line.number));
            return Ok(());
        };
        process.pid = pid;
        process.command = rest.trim();
        sink.emit(Loc::Line(line.number), &process)
    })?;
    if layout.is_none() {
        return Err(Error::skipped("empty file"));
    }
    Ok(())
}

// ---------------------------------------------------------------- sockets

enum SocketLayout {
    /// `has_user`: `netstat -e` adds User and Inode columns; `has_timer`: `netstat -o` adds
    /// a Timer column after the program.
    Netstat {
        has_user: bool,
        has_timer: bool,
    },
    Ss {
        has_netid: bool,
    },
    /// The UNIX socket section of netstat.
    Ignored,
}

#[derive(Serialize)]
struct Socket<'a> {
    /// `tcp`, `tcp6`, `udp6` (netstat) or `tcp`, `udp` (ss; from the Netid column or, when
    /// absent, from the `-t`/`-u` option in the file name).
    protocol: Option<&'a str>,
    local_address: Option<Cow<'a, str>>,
    /// None for a wildcard (`*`) and for service names (`ssh`) when names were not resolved
    /// to numbers.
    local_port: Option<u16>,
    remote_address: Option<Cow<'a, str>>,
    remote_port: Option<u16>,
    state: Option<&'a str>,
    pid: Option<u32>,
    program: Option<&'a str>,
    user: Option<&'a str>,
}

impl Record for Socket<'_> {}

/// Splits `address:port` at the last colon, so `[::]:22` and `:::22` both give `::` and 22.
/// Brackets are dropped, including those of a zoned address (`[fe80::1]%eth0` -> `fe80::1%eth0`).
fn endpoint(text: &str) -> (Option<Cow<'_, str>>, Option<u16>) {
    let Some((address, port)) = text.rsplit_once(':') else { return (Some(text.into()), None) };
    let address: Cow<str> = match address.strip_prefix('[').and_then(|a| a.split_once(']')) {
        Some((inner, "")) => inner.into(),
        Some((inner, zone)) => format!("{inner}{zone}").into(),
        None => address.into(),
    };
    ((!address.is_empty()).then_some(address), port.parse().ok())
}

/// `users:(("sshd",pid=4355,fd=3))`: the first process only (shared sockets list several).
/// ss prints the process name between quotes unescaped, so a name may hold `",pid=1,`; the
/// real pid is the one after the LAST `",pid=` of the first tuple.
fn ss_process(text: &str) -> (Option<u32>, Option<&str>) {
    let Some((_, body)) = text.split_once('"') else { return (None, None) };
    let first = body.find("),(\"").map_or(body, |end| &body[..end]);
    let (program, tail) = match first.rsplit_once("\",pid=") {
        Some(split) => split,
        None => return (None, body.split('"').next().filter(|p| !p.is_empty())),
    };
    let digits = tail.find(|c: char| !c.is_ascii_digit()).unwrap_or(tail.len());
    (tail[..digits].parse().ok(), Some(program).filter(|p| !p.is_empty()))
}

/// `4355/sshd: /usr/sbi` or `-`.
fn netstat_process(text: &str) -> (Option<u32>, Option<&str>) {
    match text.split_once('/') {
        Some((pid, program)) => (pid.trim().parse().ok(), Some(program.trim()).filter(|p| !p.is_empty())),
        None => (None, None),
    }
}

/// `netstat -o` ends a row with a timer, `off (0.00/0/0)` or `keepalive (3.52/0/0)`. The program
/// before it may contain spaces, so the timer is cut from the right.
fn without_timer(rest: &str) -> &str {
    let rest = rest.trim_end();
    match rest.rfind(" (") {
        Some(at) if rest.ends_with(')') => {
            let before = rest[..at].trim_end();
            let name_at = before.rfind(' ').map_or(0, |i| i + 1);
            if matches!(&before[name_at..], "off" | "on" | "keepalive" | "timewait") {
                before[..name_at].trim_end()
            } else {
                rest
            }
        }
        _ => rest,
    }
}

/// `ss_-tanp.txt` has no Netid column, so the option letters in the name say tcp or udp.
fn protocol_from_name(path: &str) -> Option<&'static str> {
    let options = path.rsplit('/').next()?.strip_prefix("ss_-")?.split('.').next()?;
    if options.contains('t') {
        Some("tcp")
    } else if options.contains('u') {
        Some("udp")
    } else {
        None
    }
}

fn parse_network(input: &Input, sink: &mut Sink) -> Result<()> {
    let default_protocol = protocol_from_name(input.path);
    let mut layout: Option<SocketLayout> = None;
    let mut seen = false;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        seen = true;
        if trimmed.starts_with("Active UNIX") {
            layout = Some(SocketLayout::Ignored);
            return Ok(());
        }
        if trimmed.starts_with("Active ") {
            return Ok(());
        }
        if trimmed.starts_with("Proto ") {
            let unix = trimmed.starts_with("Proto RefCnt");
            layout = Some(if unix {
                SocketLayout::Ignored
            } else {
                let has = |column: &str| trimmed.split_whitespace().any(|w| w == column);
                SocketLayout::Netstat { has_user: has("User"), has_timer: has("Timer") }
            });
            return Ok(());
        }
        if trimmed.starts_with("Netid ") || trimmed.starts_with("State ") {
            layout = Some(SocketLayout::Ss { has_netid: trimmed.starts_with("Netid") });
            return Ok(());
        }
        let mut rest: &str = trimmed;
        let socket = match &layout {
            None => return Ok(()),
            Some(SocketLayout::Ignored) => return Ok(()),
            Some(SocketLayout::Netstat { has_user, has_timer }) => {
                let protocol = word(&mut rest);
                if !protocol.is_some_and(|p| p.starts_with("tcp") || p.starts_with("udp") || p.starts_with("raw")) {
                    return Ok(());
                }
                let _queues = (word(&mut rest), word(&mut rest));
                let (Some(local), Some(remote)) = (word(&mut rest), word(&mut rest)) else {
                    sink.warn(format!("line {}: too few columns", line.number));
                    return Ok(());
                };
                // UDP rows have no state: the next word is a number, a user or `-`.
                let mut state = None;
                // A raw socket's state column is a number (its protocol), not a user.
                let raw = protocol.is_some_and(|p| p.starts_with("raw"));
                let mut peek = rest;
                let is_state = |w: &str| {
                    w.starts_with(|c: char| c.is_ascii_uppercase()) || (raw && w.bytes().all(|b| b.is_ascii_digit()))
                };
                if word(&mut peek).is_some_and(is_state) {
                    state = word(&mut rest);
                }
                let mut user = None;
                if *has_user {
                    user = word(&mut rest);
                    let _inode = word(&mut rest);
                }
                let (pid, program) = netstat_process(if *has_timer { without_timer(rest) } else { rest });
                let ((local_address, local_port), (remote_address, remote_port)) = (endpoint(local), endpoint(remote));
                Socket { protocol, local_address, local_port, remote_address, remote_port, state, pid, program, user }
            }
            Some(SocketLayout::Ss { has_netid }) => {
                let netid = if *has_netid { word(&mut rest) } else { default_protocol };
                // Unix, netlink and packet sockets are not network connections.
                if !netid.is_some_and(|n| matches!(n, "tcp" | "udp" | "raw" | "sctp" | "mptcp" | "dccp")) {
                    return Ok(());
                }
                let state = word(&mut rest);
                let _queues = (word(&mut rest), word(&mut rest));
                let (Some(local), Some(remote)) = (word(&mut rest), word(&mut rest)) else {
                    sink.warn(format!("line {}: too few columns", line.number));
                    return Ok(());
                };
                let (pid, program) = ss_process(rest);
                let ((local_address, local_port), (remote_address, remote_port)) = (endpoint(local), endpoint(remote));
                Socket {
                    protocol: netid,
                    local_address,
                    local_port,
                    remote_address,
                    remote_port,
                    state,
                    pid,
                    program,
                    user: None,
                }
            }
        };
        sink.emit(Loc::Line(line.number), &socket)
    })?;
    if !seen {
        return Err(Error::skipped("empty file"));
    }
    if layout.is_none() {
        return Err(Error::format("no netstat or ss header found"));
    }
    Ok(())
}

// ---------------------------------------------------------------- lsof

#[derive(Serialize)]
struct OpenFile<'a> {
    command: &'a str,
    pid: u32,
    /// Only for thread rows (`lsof -l` with task columns).
    tid: Option<u32>,
    task_command: Option<&'a str>,
    /// Only with `lsof -R` (CatScale runs it that way).
    ppid: Option<u32>,
    user: &'a str,
    fd: &'a str,
    file_type: Option<&'a str>,
    device: Option<&'a str>,
    size_off: Option<&'a str>,
    /// Inode, or the protocol (`TCP`) for sockets.
    node: Option<&'a str>,
    /// The NAME column: a path, or the endpoints and state for sockets.
    path: &'a str,
}

impl Record for OpenFile<'_> {}

fn parse_open_files(input: &Input, sink: &mut Sink) -> Result<()> {
    // Column in the header where the right-aligned TID ends; rows of threads have a
    // character there and rows of processes have blanks.
    let mut tid_end: Option<Option<usize>> = None;
    let mut has_ppid = false;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() {
            return Ok(());
        }
        // BusyBox lsof has no header and four tab-separated columns: pid, program, fd, name.
        let mut tabbed = text.splitn(4, '\t');
        if let (None, Some(pid), Some(command), Some(fd), Some(path)) =
            (tid_end, tabbed.next().and_then(|p| p.parse().ok()), tabbed.next(), tabbed.next(), tabbed.next())
        {
            let file = OpenFile {
                command,
                pid,
                tid: None,
                task_command: None,
                ppid: None,
                user: "",
                fd,
                file_type: None,
                device: None,
                size_off: None,
                node: None,
                path,
            };
            return sink.emit(Loc::Line(line.number), &file);
        }
        let Some(tid_end) = tid_end else {
            if !text.starts_with("COMMAND") {
                return Err(Error::format("not an lsof listing (no COMMAND header)"));
            }
            tid_end = Some(text.find("TID").map(|at| at + 3));
            has_ppid = text.split_whitespace().any(|w| w == "PPID");
            return Ok(());
        };
        let has_tid = tid_end.is_some_and(|end| text.as_bytes().get(end - 1).is_some_and(|b| !b.is_ascii_whitespace()));
        let mut rest: &str = &text;
        let command = word(&mut rest);
        let pid = word(&mut rest).and_then(|p| p.parse().ok());
        let (tid, task_command) =
            if has_tid { (word(&mut rest).and_then(|t| t.parse().ok()), word(&mut rest)) } else { (None, None) };
        let ppid = if has_ppid { word(&mut rest).and_then(|p| p.parse().ok()) } else { None };
        let (Some(command), Some(pid), Some(user), Some(fd)) = (command, pid, word(&mut rest), word(&mut rest)) else {
            sink.warn(format!("line {}: too few columns", line.number));
            return Ok(());
        };
        // Rows without a descriptor (`NOFD`) or with an unknown type leave later columns blank.
        let (mut file_type, mut device, mut size_off, mut node) = (None, None, None, None);
        if fd != "NOFD" {
            file_type = word(&mut rest);
            if fd == "DEL" {
                // Deleted mapped files have no SIZE/OFF column; their NAME keeps ` (deleted)`.
                (device, node) = (word(&mut rest), word(&mut rest));
                if node.is_none() {
                    sink.warn(format!("line {}: too few columns", line.number));
                    return Ok(());
                }
            } else if file_type != Some("unknown") {
                (device, size_off, node) = (word(&mut rest), word(&mut rest), word(&mut rest));
                if node.is_none() {
                    sink.warn(format!("line {}: too few columns", line.number));
                    return Ok(());
                }
            }
        }
        sink.emit(
            Loc::Line(line.number),
            &OpenFile {
                command,
                pid,
                tid,
                task_command,
                ppid,
                user,
                fd,
                file_type,
                device,
                size_off,
                node,
                path: rest.trim(),
            },
        )
    })?;
    if tid_end.is_none() {
        return Err(Error::skipped("empty file"));
    }
    Ok(())
}

// ---------------------------------------------------------------- lsmod

#[derive(Serialize)]
struct Module<'a> {
    module: &'a str,
    size_bytes: Option<u64>,
    used_count: Option<u32>,
    used_by: Vec<&'a str>,
}

impl Record for Module<'_> {}

fn parse_modules(input: &Input, sink: &mut Sink) -> Result<()> {
    let (mut rows, mut header) = (0u64, false);
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() {
            return Ok(());
        }
        if !header {
            let mut columns = text.split_whitespace();
            header = columns.next() == Some("Module") && columns.next() == Some("Size");
            return if header { Ok(()) } else { Err(Error::format("not an lsmod listing (no Module header)")) };
        }
        let mut rest: &str = &text;
        let (Some(module), Some(size), Some(used)) = (word(&mut rest), word(&mut rest), word(&mut rest)) else {
            sink.warn(format!("line {}: too few columns", line.number));
            return Ok(());
        };
        rows += 1;
        let used_by = word(&mut rest).map(|list| list.split(',').filter(|m| !m.is_empty()).collect());
        sink.emit(
            Loc::Line(line.number),
            &Module {
                module,
                size_bytes: size.parse().ok(),
                used_count: used.parse().ok(),
                used_by: used_by.unwrap_or_default(),
            },
        )
    })?;
    if rows == 0 {
        return Err(Error::skipped("no modules listed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // The test host has no parent directory, so paths are given without the `../` the real
    // patterns have; the parsers only look at the file name.
    use super::*;
    use crate::testing::{fixture, run};

    fn snapshot(artifact: &Artifact, path: &str, fixture_name: &str) -> String {
        run(artifact, path, &fixture(fixture_name), 0)
    }

    #[test]
    fn ps_auxwww() {
        insta::assert_snapshot!(snapshot(
            &PROCESSES,
            "../live_response/process/ps_auxwww.txt",
            "live-processes/ps_auxwww.txt"
        ));
    }

    #[test]
    fn ps_ef() {
        insta::assert_snapshot!(snapshot(
            &PROCESSES,
            "../live_response/process/ps_-ef.txt",
            "live-processes/ps_-ef.txt"
        ));
    }

    #[test]
    fn ps_lstart() {
        insta::assert_snapshot!(snapshot(
            &PROCESSES,
            "../live_response/process/ps_-eo_user_pid_ppid_pcpu_pmem_tty_stat_lstart_args.txt",
            "live-processes/ps_lstart.txt"
        ));
    }

    #[test]
    fn ps_etime() {
        insta::assert_snapshot!(snapshot(
            &PROCESSES,
            "../live_response/process/ps_-eo_user_pid_ppid_pcpu_pmem_tty_stat_etime_args.txt",
            "live-processes/ps_etime.txt"
        ));
    }

    #[test]
    fn ps_edge_cases() {
        insta::assert_snapshot!(snapshot(
            &PROCESSES,
            "../live_response/process/ps_auxwww.txt",
            "live-processes/edge.txt"
        ));
    }

    #[test]
    fn netstat_lpeanut() {
        insta::assert_snapshot!(snapshot(
            &NETWORK,
            "../live_response/network/netstat_-lpeanut.txt",
            "live-network/netstat_-lpeanut.txt"
        ));
    }

    #[test]
    fn netstat_anp_stops_at_unix_sockets() {
        insta::assert_snapshot!(snapshot(
            &NETWORK,
            "../live_response/network/netstat_-anp.txt",
            "live-network/netstat_-anp.txt"
        ));
    }

    #[test]
    fn ss_tanp() {
        insta::assert_snapshot!(snapshot(
            &NETWORK,
            "../live_response/network/ss_-tanp.txt",
            "live-network/ss_-tanp.txt"
        ));
    }

    #[test]
    fn ss_anp_skips_non_inet_sockets() {
        insta::assert_snapshot!(snapshot(&NETWORK, "../live_response/network/ss_-anp.txt", "live-network/ss_-anp.txt"));
    }

    #[test]
    fn ss_ulnp() {
        insta::assert_snapshot!(snapshot(
            &NETWORK,
            "../live_response/network/ss_-ulnp.txt",
            "live-network/ss_-ulnp.txt"
        ));
    }

    #[test]
    fn network_edge_cases() {
        insta::assert_snapshot!(snapshot(&NETWORK, "../live_response/network/ss_-tap.txt", "live-network/edge_ss.txt"));
        insta::assert_snapshot!(snapshot(
            &NETWORK,
            "../live_response/network/netstat_-a.txt",
            "live-network/edge_netstat.txt"
        ));
    }

    #[test]
    fn lsof() {
        insta::assert_snapshot!(snapshot(
            &OPEN_FILES,
            "../live_response/process/lsof_-nPl.txt",
            "live-open-files/lsof_-nPl.txt"
        ));
    }

    #[test]
    fn lsof_edge_cases() {
        insta::assert_snapshot!(snapshot(
            &OPEN_FILES,
            "../live_response/process/lsof_-nPl.txt",
            "live-open-files/edge.txt"
        ));
    }

    const CATSCALE: &str = "catscale/host-20261112-1838";

    fn catscale(artifact: &Artifact, section: &str, name: &str) -> String {
        let path = format!("../{section}/host-20261112-1838-{name}.txt");
        snapshot(artifact, &path, &format!("{CATSCALE}-{name}.txt"))
    }

    #[test]
    fn catscale_ps() {
        insta::assert_snapshot!(catscale(&PROCESSES, "Process_and_Network", "processes-axwwSo"));
    }

    #[test]
    fn catscale_ss_anepo() {
        insta::assert_snapshot!(catscale(&NETWORK, "Process_and_Network", "ss-anepo"));
    }

    #[test]
    fn catscale_netstat_antup() {
        insta::assert_snapshot!(catscale(&NETWORK, "Process_and_Network", "netstat-antup"));
    }

    #[test]
    fn catscale_netstat_pvwanoee_has_a_timer_after_the_program() {
        let out = catscale(&NETWORK, "Process_and_Network", "netstat-pvWanoee");
        assert!(out.contains("\"program\":\"nc\"") && !out.contains("off ("), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn catscale_netstat_an_has_no_program() {
        insta::assert_snapshot!(catscale(&NETWORK, "Process_and_Network", "netstat-an"));
    }

    #[test]
    fn catscale_lsof_has_a_ppid_column() {
        let out = catscale(&OPEN_FILES, "Process_and_Network", "lsof-list-open-files");
        assert!(out.contains("\"ppid\":468") && out.contains("\"user\":\"root\""), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn catscale_lsmod() {
        insta::assert_snapshot!(catscale(&MODULES, "System_Info", "lsmod"));
    }

    #[test]
    fn catscale_names_are_matched_beside_the_root() {
        use nixcavate_source::glob::Pattern;
        let matches = |a: &Artifact, path: &str| a.paths.iter().any(|p| Pattern::new(p).matches(path));
        assert!(matches(&PROCESSES, "Process_and_Network/web01-20261112-1838-processes-axwwSo.txt"));
        assert!(matches(&NETWORK, "Process_and_Network/web01-20261112-1838-ss-anepo.txt"));
        assert!(matches(&MODULES, "System_Info/web01-20261112-1838-lsmod.txt"));
        assert!(!matches(&MODULES, "System_Info/web01-20261112-1838-modinfo.txt"));
    }

    #[test]
    fn lsmod() {
        insta::assert_snapshot!(snapshot(&MODULES, "../live_response/system/lsmod.txt", "live-modules/lsmod.txt"));
    }

    #[test]
    fn lsof_deleted_rows_have_no_size_column() {
        let data = b"COMMAND     PID   TID TASKCMD       USER   FD      TYPE             DEVICE  SIZE/OFF       NODE NAME\nimplant    4242                     0  DEL       REG                0,1             2392073 /memfd:x (deleted)\n";
        let out = run(&OPEN_FILES, "../live_response/process/lsof_-nPl.txt", data, 0);
        assert!(
            out.contains("\"device\":\"0,1\",\"size_off\":null,\"node\":\"2392073\",\"path\":\"/memfd:x (deleted)\""),
            "{out}"
        );
    }

    /// BusyBox `lsof` (Alpine) prints no header: pid, program, descriptor and name, with tabs.
    #[test]
    fn busybox_lsof_has_four_tab_separated_columns() {
        let data = b"1\t/bin/busybox\t0\t/dev/null\n23\t/usr/sbin/sshd\t3\tsocket:[220614076]\n";
        let out = run(&OPEN_FILES, "../live_response/process/lsof_-nPl.txt", data, 0);
        assert!(!out.contains("failed") && !out.contains("warning"), "{out}");
        let row = r#""command":"/usr/sbin/sshd","pid":23,"tid":null,"task_command":null,"ppid":null,"user":"","fd":"3","file_type":null,"device":null,"size_off":null,"node":null,"path":"socket:[220614076]""#;
        assert!(out.contains(row), "{out}");
    }

    #[test]
    fn ss_process_name_cannot_forge_the_pid() {
        assert_eq!(ss_process("users:((\"x\",pid=1,\",pid=31337,fd=3))"), (Some(31337), Some("x\",pid=1,")));
        assert_eq!(ss_process("users:((\"a\",pid=7,fd=3),(\"b\",pid=8,fd=4))"), (Some(7), Some("a")));
    }

    #[test]
    fn netstat_raw_rows_keep_the_user() {
        let data = b"Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name\nraw        0      0 0.0.0.0:1             0.0.0.0:*               7           root       12345      42/ping\n";
        let out = run(&NETWORK, "../live_response/network/netstat_-lpeanut.txt", data, 0);
        assert!(
            out.contains("\"state\":\"7\"") && out.contains("\"user\":\"root\"") && out.contains("\"pid\":42"),
            "{out}"
        );
    }

    #[test]
    fn lsmod_header_is_found_by_content() {
        let out =
            run(&MODULES, "../live_response/system/lsmod.txt", b"\n\nModule  Size  Used by\nnf_tables 100 2 a,b\n", 0);
        assert!(out.contains("\"module\":\"nf_tables\""), "{out}");
        assert!(run(&MODULES, "../live_response/system/lsmod.txt", b"nf_tables 100 2\n", 0).contains("failed"));
    }

    #[test]
    fn lsmod_header_only_is_skipped() {
        insta::assert_snapshot!(run(
            &MODULES,
            "../live_response/system/lsmod.txt",
            b"Module                  Size  Used by\n",
            0
        ));
    }

    #[test]
    fn empty_and_garbage_inputs() {
        for artifact in [&PROCESSES, &NETWORK, &OPEN_FILES, &MODULES] {
            let path = artifact.paths[0];
            insta::assert_snapshot!(format!("empty_{}", artifact.id), run(artifact, path, b"", 0));
            insta::assert_snapshot!(
                format!("garbage_{}", artifact.id),
                run(artifact, path, b"\x00\xff garbage\nmore garbage 12 34\n", 0)
            );
        }
    }

    #[test]
    fn truncated_and_flipped_input_does_not_panic() {
        let cases = [
            (&PROCESSES, "live-processes/edge.txt"),
            (&NETWORK, "live-network/edge_ss.txt"),
            (&NETWORK, "live-network/netstat_-lpeanut.txt"),
            (&OPEN_FILES, "live-open-files/edge.txt"),
            (&MODULES, "live-modules/lsmod.txt"),
        ];
        for (artifact, name) in cases {
            let data = fixture(name);
            let path = artifact.paths[0];
            for len in 0..data.len() {
                run(artifact, path, &data[..len], 0);
            }
            for i in (0..data.len()).step_by(7) {
                let mut flipped = data.clone();
                flipped[i] ^= 0xa5;
                run(artifact, path, &flipped, 0);
            }
        }
    }
}
