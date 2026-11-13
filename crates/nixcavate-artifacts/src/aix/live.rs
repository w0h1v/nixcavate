//! AIX command output collected by UAC live response: `netstat` (with `-A` for the protocol
//! control block address), `rmsock` (which process holds a socket), `lssrc -a` (System Resource
//! Controller subsystems) and `genkex` (kernel extensions). `ps` is read by `live-processes`.
//!
//! The layouts are written from the commands' documented output and public sample listings of
//! `netstat -an` and `lssrc -a`; **no real AIX output was available**: synthetic only. A row that
//! does not fit is skipped by its header rules or named in a warning, never guessed.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, AIX};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const NETWORK: Artifact = Artifact::new(
    "aix-live-network",
    "Sockets captured by UAC on AIX (netstat)",
    Category::Live,
    AIX,
    &[
        "../live_response/network/netstat_-an.txt",
        "../live_response/network/netstat_-Aan.txt",
        "../live_response/network/netstat_-a.txt",
        "../live_response/network/netstat_-anp_tcp.txt",
        "../live_response/network/netstat_-anp_udp.txt",
    ],
    parse_network,
);
pub const RMSOCK: Artifact = Artifact::new(
    "aix-live-rmsock",
    "Socket owners captured by UAC on AIX (rmsock)",
    Category::Live,
    AIX,
    &["../live_response/network/rmsock_tcpcb.txt"],
    parse_rmsock,
);
pub const SRC: Artifact = Artifact::new(
    "aix-lssrc",
    "System Resource Controller subsystems (lssrc -a)",
    Category::Live,
    AIX,
    &["../live_response/network/lssrc_-a.txt"],
    parse_lssrc,
);
pub const KERNEL_EXTENSIONS: Artifact = Artifact::new(
    "aix-genkex",
    "Loaded kernel extensions (genkex)",
    Category::Live,
    AIX,
    &["../live_response/system/genkex.txt"],
    parse_genkex,
);

// ---------------------------------------------------------------- netstat

#[derive(Serialize)]
struct Socket<'a> {
    /// The protocol control block address (`netstat -A` only), the key `rmsock` takes.
    pcb: Option<&'a str>,
    protocol: &'a str,
    recv_q: Option<u64>,
    send_q: Option<u64>,
    local_address: Option<&'a str>,
    local_port: Option<u16>,
    remote_address: Option<&'a str>,
    remote_port: Option<u16>,
    state: Option<&'a str>,
}

impl Record for Socket<'_> {}

/// `10.0.0.5.22`, `*.22`, `::1.25`, `fe80::1.123`: the port follows the last dot. `*.*` has neither.
fn endpoint(text: &str) -> (Option<&str>, Option<u16>) {
    let Some((address, port)) = text.rsplit_once('.') else { return (Some(text), None) };
    let address = if address == "*" || address.is_empty() { None } else { Some(address) };
    (address, port.parse().ok())
}

fn parse_network(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut with_pcb: Option<bool> = None;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let words: Vec<&str> = text.split_whitespace().collect();
        let Some(first) = words.first() else { return Ok(()) };
        if *first == "Active" {
            // The UNIX domain section follows; its rows are not network connections.
            if text.contains("UNIX") {
                with_pcb = None;
            }
            return Ok(());
        }
        if *first == "Proto" {
            with_pcb = Some(false);
            return Ok(());
        }
        if *first == "PCB/ADDR" {
            with_pcb = Some(true);
            return Ok(());
        }
        let Some(has_pcb) = with_pcb else { return Ok(()) };
        let (pcb, rest) = if has_pcb { (words.first().copied(), &words[1..]) } else { (None, &words[..]) };
        let [protocol, recv_q, send_q, local, remote, state @ ..] = rest else { return Ok(()) };
        if !(protocol.starts_with("tcp")
            || protocol.starts_with("udp")
            || protocol.starts_with("raw")
            || protocol.starts_with("icmp"))
        {
            return Ok(());
        }
        let ((local_address, local_port), (remote_address, remote_port)) = (endpoint(local), endpoint(remote));
        sink.emit(
            Loc::Line(line.number),
            &Socket {
                pcb,
                protocol,
                recv_q: recv_q.parse().ok(),
                send_q: send_q.parse().ok(),
                local_address,
                local_port,
                remote_address,
                remote_port,
                state: state.first().copied(),
            },
        )
    })
}

// ---------------------------------------------------------------- rmsock

#[derive(Serialize)]
struct SocketOwner<'a> {
    pcb: &'a str,
    socket: Option<&'a str>,
    pid: Option<u32>,
    program: Option<&'a str>,
}

impl Record for SocketOwner<'_> {}

/// `PCB/ADDR:f1000e000123a8b8 The socket 0xf1000e000123a800 is being held by proccess 5832144 (sshd).`
/// (IBM's message spells it `proccess`; both spellings are accepted.)
fn parse_rmsock(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let Some(rest) = text.trim().strip_prefix("PCB/ADDR:") else { return Ok(()) };
        let (pcb, message) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        let words: Vec<&str> = message.split_whitespace().collect();
        let socket = words.iter().position(|w| *w == "socket").and_then(|i| words.get(i + 1)).copied();
        let held = words.iter().position(|w| matches!(*w, "proccess" | "process"));
        let pid = held.and_then(|i| words.get(i + 1)).and_then(|p| p.parse().ok());
        let program = held.and_then(|i| words.get(i + 2)).map(|p| p.trim_matches(|c| c == '(' || c == ')' || c == '.'));
        if pid.is_none() {
            return Ok(()); // an error line (no such socket)
        }
        sink.emit(Loc::Line(line.number), &SocketOwner { pcb, socket, pid, program })
    })
}

// ---------------------------------------------------------------- lssrc

#[derive(Serialize)]
struct Subsystem<'a> {
    name: &'a str,
    group: Option<&'a str>,
    pid: Option<u32>,
    status: &'a str,
}

impl Record for Subsystem<'_> {}

fn parse_lssrc(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut seen_header = false;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let words: Vec<&str> = text.split_whitespace().collect();
        if words.is_empty() {
            return Ok(());
        }
        if words.first() == Some(&"Subsystem") {
            seen_header = true;
            return Ok(());
        }
        if !seen_header {
            return Ok(());
        }
        // Group and PID are blank for some subsystems: a PID is the numeric word.
        let (name, rest) = (words[0], &words[1..]);
        let (status, middle) = match rest.split_last() {
            Some((status, middle)) => (*status, middle),
            None => {
                sink.warn(format!("line {}: no status", line.number));
                return Ok(());
            }
        };
        let pid = middle.iter().find_map(|w| w.parse::<u32>().ok());
        let group = middle.iter().find(|w| w.parse::<u32>().is_err()).copied();
        sink.emit(Loc::Line(line.number), &Subsystem { name, group, pid, status })
    })
}

// ---------------------------------------------------------------- genkex

#[derive(Serialize)]
struct KernelExtension<'a> {
    address: &'a str,
    size: &'a str,
    path: &'a str,
}

impl Record for KernelExtension<'_> {}

fn parse_genkex(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let mut words = text.split_whitespace();
        let (Some(address), Some(size)) = (words.next(), words.next()) else { return Ok(()) };
        let hex = |w: &str| !w.is_empty() && w.len() <= 16 && w.bytes().all(|b| b.is_ascii_hexdigit());
        let path = text.trim().splitn(3, char::is_whitespace).nth(2).map(str::trim).unwrap_or("");
        if !hex(address) || !hex(size) || path.is_empty() {
            return Ok(()); // headers and anything else
        }
        sink.emit(Loc::Line(line.number), &KernelExtension { address, size, path })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;

    #[test]
    fn netstat_with_and_without_pcb() {
        let plain = b"Active Internet connections (including servers)\nProto Recv-Q Send-Q  Local Address          Foreign Address        (state)\ntcp4       0      0  *.22                   *.*                    LISTEN\ntcp4       0      0  10.0.0.5.22            203.0.113.9.51234      ESTABLISHED\ntcp6       0      0  ::1.25                 *.*                    LISTEN\nudp4       0      0  *.123                  *.*\nActive UNIX domain sockets\nSADR/PCB         Type   Recv-Q Send-Q    Inode     Conn     Refs  Nextref Addr\n";
        let out = run(&NETWORK, "../live_response/network/netstat_-an.txt", plain, 0);
        assert!(out.contains(r#""local_address":"10.0.0.5","local_port":22,"remote_address":"203.0.113.9","remote_port":51234,"state":"ESTABLISHED""#), "{out}");
        assert!(out.contains(r#""local_address":"::1","local_port":25"#), "{out}");
        assert_eq!(out.matches("\"protocol\"").count(), 4, "{out}");
        insta::assert_snapshot!(out);
        let with = b"PCB/ADDR         Proto Recv-Q Send-Q  Local Address      Foreign Address    (state)\nf1000e0001a2b3b8 tcp4       0      0  *.22               *.*                LISTEN\n";
        let out = run(&NETWORK, "../live_response/network/netstat_-Aan.txt", with, 0);
        assert!(out.contains(r#""pcb":"f1000e0001a2b3b8","protocol":"tcp4""#), "{out}");
    }

    #[test]
    fn rmsock_lssrc_genkex() {
        let out = run(&RMSOCK, "../live_response/network/rmsock_tcpcb.txt", b"PCB/ADDR:f1000e0001a2b3b8 The socket 0xf1000e0001a2b000 is being held by proccess 5832144 (sshd).\nPCB/ADDR:f1000e0001a2b3c8 error\n", 0);
        assert!(out.contains(r#""pid":5832144,"program":"sshd""#) && out.matches("\"pcb\"").count() == 1, "{out}");
        let src = b"Subsystem         Group            PID          Status \n srcmstr                           2556216      active\n syslogd          ras              3014824      active\n sshd             ssh                           inoperative\n";
        let out = run(&SRC, "../live_response/network/lssrc_-a.txt", src, 0);
        assert!(
            out.contains(r#""name":"srcmstr","group":null,"pid":2556216"#)
                && out.contains(r#""name":"sshd","group":"ssh","pid":null,"status":"inoperative""#),
            "{out}"
        );
        let gx = b"Text address     Size File\nf1000000c0310000    f000 /usr/lib/drivers/nfs.ext\n    1a30000   a1b0 /tmp/.x/rk.ext\n";
        let out = run(&KERNEL_EXTENSIONS, "../live_response/system/genkex.txt", gx, 0);
        assert_eq!(out.matches("\"path\"").count(), 2, "{out}");
    }

    /// AIX's `ps -ef` and `ps auxwww` print an old start time as two words (`Mar 10`).
    #[test]
    fn aix_ps_start_times_may_be_two_words() {
        let data = b"     UID    PID   PPID   C    STIME    TTY  TIME CMD
    root      1      0   0   Mar 10      -  0:12 /etc/init
    root 3211264      1   0 01:02:03      -  0:00 /usr/sbin/sshd
  alice 8913 3211264   0 09:12:34  pts/1  0:00 -ksh
";
        let out = run(&crate::linux::uac_live::PROCESSES, "../live_response/process/ps_-ef.txt", data, 0);
        assert!(out.contains(r#""started":"Mar 10","cpu_time":"0:12","elapsed":null,"command":"/etc/init""#), "{out}");
        assert!(
            out.contains(r#""tty":"-","state":null,"started":"01:02:03""#) && out.contains(r#""command":"-ksh""#),
            "{out}"
        );
        let data = b"USER        PID %CPU %MEM   SZ  RSS    TTY STAT    STIME  TIME COMMAND
root          1  0.0  0.0  724  788      - A      Mar 10  0:12 /etc/init
root    3211264  0.0  0.0 1100 1200      - A     01:02:03  0:00 /usr/sbin/sshd -D
";
        let out = run(&crate::linux::uac_live::PROCESSES, "../live_response/process/ps_auxwww.txt", data, 0);
        assert!(out.contains(r#""started":"Mar 10""#) && out.contains(r#""command":"/usr/sbin/sshd -D""#), "{out}");
    }

    #[test]
    fn hostile() {
        for data in [
            &b""[..],
            b"Proto\ntcp\ntcp4 1 2\n",
            b"PCB/ADDR\nx tcp4 a b c d e\n",
            b"Subsystem\n x\n",
            b"\xff\xfe\n",
            &[b'.'; 5000][..],
        ] {
            for artifact in [&NETWORK, &RMSOCK, &SRC, &KERNEL_EXTENSIONS] {
                let _ = run(artifact, "../live_response/network/netstat_-an.txt", data, 0);
            }
        }
    }
}
