//! Command output saved by `vm-support` (`commands/`, named after the command with spaces turned
//! into dashes: `localcli_network-ip-connection-list.txt`) and by UAC (`live_response/`, spaces
//! turned into underscores: `esxcli_network_ip_connection_list.txt`). The layouts are those of
//! `esxcli network ip connection list`, `ps -cPTgjstz`, `esxcli vm process list` and
//! `vim-cmd vmsvc/getallvms`. Each parser checks the header first and refuses a file whose
//! header it does not know, because the same command prints different columns between builds.

use crate::text::lossy;
use crate::{Artifact, Category, Input, ESXI};
use nixcavate_core::{Error, Loc, Record, Result, Sink};
use serde::Serialize;

pub const CONNECTIONS: Artifact = Artifact::new(
    "esxi-live-connections",
    "TCP and UDP connections saved from `esxcli network ip connection list`",
    Category::Live,
    ESXI,
    &[
        "commands/localcli_network-ip-connection-list.txt",
        "commands/esxcli_network-ip-connection-list.txt",
        "../live_response/network/esxcli_network_ip_connection_list.txt",
    ],
    parse_connections,
);

pub const PROCESSES: Artifact = Artifact::new(
    "esxi-live-processes",
    "ESXi worlds and processes saved from `ps`",
    Category::Live,
    ESXI,
    &["commands/ps_-cPTgjstz.txt", "../live_response/process/ps_-P_-T_-c_-g_-s_-t_-J.txt"],
    parse_processes,
);

pub const VM_PROCESSES: Artifact = Artifact::new(
    "esxi-live-vm-processes",
    "Running virtual machines saved from `esxcli vm process list`",
    Category::Live,
    ESXI,
    &[
        "commands/localcli_vm-process-list.txt",
        "commands/esxcli_vm-process-list.txt",
        "../live_response/vms/esxcli_vm_process_list.txt",
    ],
    parse_vm_processes,
);

pub const VM_LIST: Artifact = Artifact::new(
    "esxi-live-vm-list",
    "Registered virtual machines saved from `vim-cmd vmsvc/getallvms`",
    Category::Live,
    ESXI,
    &["commands/vim-cmd_vmsvc-getallvms.txt", "../live_response/vms/vim-cmd_vmsvc_getallvms.txt"],
    parse_vm_list,
);

/// The first non-blank line and the lines after it, numbered from 1.
fn body(text: &str) -> Option<(&str, impl Iterator<Item = (u64, &str)>)> {
    let mut lines = text.lines().enumerate();
    let (_, header) = lines.by_ref().find(|(_, l)| !l.trim().is_empty())?;
    Some((header, lines.map(|(i, l)| (i as u64 + 1, l))))
}

/// `127.0.0.1:8309`, `[::]:427`, `0.0.0.0:0`: the address and the port.
fn endpoint(text: &str) -> (&str, Option<u16>) {
    match text.rsplit_once(':') {
        Some((address, port)) => (address.trim_start_matches('[').trim_end_matches(']'), port.parse().ok()),
        None => (text, None),
    }
}

#[derive(Serialize)]
struct Connection<'a> {
    protocol: &'a str,
    recv_queue: Option<u64>,
    send_queue: Option<u64>,
    local_address: &'a str,
    local_port: Option<u16>,
    remote_address: &'a str,
    remote_port: Option<u16>,
    state: &'a str,
    /// The VMkernel world that owns the socket (a process id on other systems).
    world_id: Option<u64>,
    congestion_algorithm: &'a str,
    world_name: &'a str,
}

impl Record for Connection<'_> {}

fn parse_connections(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(input.data);
    let Some((header, rows)) = body(&text) else { return Err(Error::skipped("empty file")) };
    if !header.starts_with("Proto") || !header.contains("Local Address") {
        return Err(Error::format("not `esxcli network ip connection list` output: unrecognised header"));
    }
    for (number, row) in rows {
        let mut words = row.split_whitespace();
        let Some(protocol) = words.next().filter(|p| p.starts_with("tcp") || p.starts_with("udp")) else {
            continue;
        };
        let rest: Vec<&str> = words.collect();
        let (Some(local), Some(remote)) = (rest.get(2), rest.get(3)) else {
            sink.warn(format!("line {number}: too few columns"));
            continue;
        };
        // A UDP socket has no state: the world id follows the addresses directly.
        let state_at = 4;
        let has_state = rest.get(state_at).is_some_and(|w| w.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'));
        let tail = &rest[(state_at + usize::from(has_state)).min(rest.len())..];
        let (local_address, local_port) = endpoint(local);
        let (remote_address, remote_port) = endpoint(remote);
        sink.emit(
            Loc::Line(number),
            &Connection {
                protocol,
                recv_queue: rest.first().and_then(|w| w.parse().ok()),
                send_queue: rest.get(1).and_then(|w| w.parse().ok()),
                local_address,
                local_port,
                remote_address,
                remote_port,
                state: if has_state { rest[state_at] } else { "" },
                world_id: tail.first().and_then(|w| w.parse().ok()),
                congestion_algorithm: tail.get(1).copied().unwrap_or_default(),
                world_name: tail.get(2).copied().unwrap_or_default(),
            },
        )?;
    }
    Ok(())
}

#[derive(Serialize)]
struct Process<'a> {
    world_id: Option<u64>,
    cartel_id: Option<u64>,
    world_name: &'a str,
    group_id: Option<u64>,
    parent_group_id: Option<u64>,
    session_id: Option<u64>,
    parent_cartel_id: Option<u64>,
    /// `SI` system idle, `S` system, `U` user world, `UX` user world with a parent, `SH`...
    world_type: &'a str,
    state: &'a str,
    wait: &'a str,
    cpu: &'a str,
    /// CPU time as `ps` prints it.
    cpu_time: &'a str,
    command: &'a str,
}

impl Record for Process<'_> {}

fn parse_processes(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(input.data);
    let Some((header, rows)) = body(&text) else { return Err(Error::skipped("empty file")) };
    let expected = "WID CID WorldName GID PGID SID PCID Type State Wait CPU Time Command";
    if header.split_whitespace().collect::<Vec<_>>().join(" ") != expected {
        return Err(Error::format("not `ps -cPTgjstz` output: unrecognised header"));
    }
    for (number, row) in rows {
        let mut w = row.split_whitespace();
        let fields: Vec<&str> = w.by_ref().take(12).collect();
        if fields.len() < 12 {
            if !row.trim().is_empty() {
                sink.warn(format!("line {number}: too few columns"));
            }
            continue;
        }
        // The command is the rest of the line as printed, spaces and all.
        let command = row
            .split_whitespace()
            .take(12)
            .fold(row.trim_start(), |rest, word| rest.strip_prefix(word).unwrap_or(rest).trim_start());
        let num = |i: usize| fields[i].parse().ok();
        sink.emit(
            Loc::Line(number),
            &Process {
                world_id: num(0),
                cartel_id: num(1),
                world_name: fields[2],
                group_id: num(3),
                parent_group_id: num(4),
                session_id: num(5),
                parent_cartel_id: num(6),
                world_type: fields[7],
                state: fields[8],
                wait: fields[9],
                cpu: fields[10],
                cpu_time: fields[11],
                command: command.trim_end(),
            },
        )?;
    }
    Ok(())
}

#[derive(Serialize)]
struct RunningVm<'a> {
    display_name: &'a str,
    world_id: Option<u64>,
    process_id: Option<u64>,
    vmx_cartel_id: Option<u64>,
    uuid: &'a str,
    config_file: &'a str,
}

impl Record for RunningVm<'_> {}

fn parse_vm_processes(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(input.data);
    if text.trim().is_empty() {
        return Err(Error::skipped("empty file"));
    }
    // Blocks: `NAME:` at the start of a line, then indented `Key: value` lines.
    // (line number, name, the `Key: value` lines below it)
    type Block<'a> = (u64, &'a str, Vec<(&'a str, &'a str)>);
    let mut blocks: Vec<Block> = Vec::new();
    for (number, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            match (blocks.last_mut(), line.trim().split_once(": ")) {
                (Some(block), Some((key, value))) => block.2.push((key, value.trim())),
                (Some(_), None) => {}
                (None, _) => sink.warn(format!("line {}: a field before any VM name", number + 1)),
            }
        } else if let Some(name) = line.trim_end().strip_suffix(':') {
            blocks.push((number as u64 + 1, name, Vec::new()));
        } else {
            return Err(Error::format("not `esxcli vm process list` output: a line is neither a name nor a field"));
        }
    }
    for (number, name, fields) in blocks {
        let get = |key: &str| fields.iter().find(|(k, _)| *k == key).map_or("", |(_, v)| *v);
        sink.emit(
            Loc::Line(number),
            &RunningVm {
                display_name: if get("Display Name").is_empty() { name } else { get("Display Name") },
                world_id: get("World ID").parse().ok(),
                process_id: get("Process ID").parse().ok(),
                vmx_cartel_id: get("VMX Cartel ID").parse().ok(),
                uuid: get("UUID"),
                config_file: get("Config File"),
            },
        )?;
    }
    Ok(())
}

#[derive(Serialize)]
struct ListedVm<'a> {
    vmid: Option<u64>,
    name: &'a str,
    /// `[datastore] folder/name.vmx`.
    file: &'a str,
    guest_os: &'a str,
    /// The virtual hardware version (`vmx-14`).
    hardware_version: &'a str,
    annotation: &'a str,
}

impl Record for ListedVm<'_> {}

fn parse_vm_list(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(input.data);
    let Some((header, rows)) = body(&text) else { return Err(Error::skipped("empty file")) };
    let names = ["Vmid", "Name", "File", "Guest OS", "Version", "Annotation"];
    let starts: Vec<Option<usize>> = names.iter().map(|n| header.find(n)).collect();
    if starts[0] != Some(0) || starts[1].is_none() || starts[2].is_none() {
        return Err(Error::format("not `vim-cmd vmsvc/getallvms` output: unrecognised header"));
    }
    let cell = |row: &'_ str, i: usize| -> String {
        let Some(from) = starts[i] else { return String::new() };
        let to = starts.iter().skip(i + 1).flatten().copied().find(|&s| s > from).unwrap_or(row.len());
        row.get(from..to.min(row.len())).unwrap_or_default().trim().to_string()
    };
    for (number, row) in rows {
        if row.trim().is_empty() {
            continue;
        }
        let vmid = cell(row, 0).parse().ok();
        if vmid.is_none() {
            sink.warn(format!("line {number}: not a VM row (a wrapped annotation or a message)"));
            continue;
        }
        let (name, file, guest_os, version, note) =
            (cell(row, 1), cell(row, 2), cell(row, 3), cell(row, 4), cell(row, 5));
        sink.emit(
            Loc::Line(number),
            &ListedVm {
                vmid,
                name: &name,
                file: &file,
                guest_os: &guest_os,
                hardware_version: &version,
                annotation: &note,
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn connections_tcp_and_udp() {
        let out = run(
            &CONNECTIONS,
            "commands/localcli_network-ip-connection-list.txt",
            &fixture("esxi-live/connections.txt"),
            0,
        );
        insta::assert_snapshot!(out);
    }

    #[test]
    fn processes_keep_the_whole_command() {
        let out = run(&PROCESSES, "commands/ps_-cPTgjstz.txt", &fixture("esxi-live/ps.txt"), 0);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn running_and_registered_vms() {
        let out =
            run(&VM_PROCESSES, "commands/localcli_vm-process-list.txt", &fixture("esxi-live/vm-process-list.txt"), 0);
        insta::assert_snapshot!(out);
        let out = run(&VM_LIST, "commands/vim-cmd_vmsvc-getallvms.txt", &fixture("esxi-live/getallvms.txt"), 0);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn unknown_headers_are_refused_not_guessed() {
        for (artifact, path) in [
            (&CONNECTIONS, "commands/localcli_network-ip-connection-list.txt"),
            (&PROCESSES, "commands/ps_-cPTgjstz.txt"),
            (&VM_LIST, "commands/vim-cmd_vmsvc-getallvms.txt"),
        ] {
            let out = run(artifact, path, b"PID TTY TIME CMD\n1 ? 0:00 init\n", 0);
            assert!(out.contains("--- failed: not "), "{out}");
            assert!(run(artifact, path, b"", 0).contains("skipped"));
        }
    }

    #[test]
    fn damaged_inputs_do_not_panic() {
        for (artifact, path, name) in [
            (&CONNECTIONS, "commands/localcli_network-ip-connection-list.txt", "esxi-live/connections.txt"),
            (&PROCESSES, "commands/ps_-cPTgjstz.txt", "esxi-live/ps.txt"),
            (&VM_PROCESSES, "commands/localcli_vm-process-list.txt", "esxi-live/vm-process-list.txt"),
            (&VM_LIST, "commands/vim-cmd_vmsvc-getallvms.txt", "esxi-live/getallvms.txt"),
        ] {
            let data = fixture(name);
            for n in 0..=data.len() {
                run(artifact, path, &data[..n], 0);
            }
            for i in (0..data.len()).step_by(3) {
                let mut flipped = data.clone();
                flipped[i] ^= 0xff;
                run(artifact, path, &flipped, 0);
            }
        }
    }
}
