//! VMware ESXi artifacts: the host's text logs, configuration and state files, installed VIBs,
//! and the command output `vm-support` and UAC save. A `vm-support` bundle is a folder
//! (`esx-<host>-<date>-<id>/`) that mirrors the host's file system, plus `commands/`, so it is
//! read like any other collection; see `frag` for the pieces it splits large files into.
//!
//! Sources: the layout of a `vm-support` bundle and of UAC's `esxi` collection was taken from real public
//! ones (listed in `docs/LIMITATIONS.md`) and from UAC 3.4.0's `artifacts/` (`supported_os: [esxi]`:
//! `files/logs/var_log.yaml`, `files/logs/var_run_log.yaml`, `files/system/etc.yaml` and the
//! `live_response/*/esxcli.yaml` command lists), https://github.com/tclahr/uac.
//!
//! ESXi shares several formats with other systems and uses their artifacts: `passwd`, `group`,
//! `shadow`, `hosts`, `resolv-conf`, `sshd-config`, `cron` (root's crontab is
//! `var/spool/cron/crontabs/root`) and `authorized-keys` (`etc/ssh/keys-<user>/`).

pub mod config;
pub mod frag;
pub mod line;
pub mod live;
pub mod logs;
pub mod packages;
pub mod xml;

use crate::Artifact;
use crate::Input;
use nixcavate_core::Timestamp;

pub static ARTIFACTS: &[Artifact] = &[
    logs::SHELL,
    logs::AUTH,
    logs::HOSTD,
    logs::VOB,
    logs::VMKERNEL,
    logs::DAEMON_LOG,
    logs::SYSLOG,
    logs::VM_LOG,
    logs::SYSBOOT,
    packages::VIB,
    packages::VIB_LIST,
    config::ESX_CONF,
    config::HOST_CONFIG,
    config::VM_INVENTORY,
    config::PERMISSIONS,
    config::FIREWALL_RULES,
    config::RC_LOCAL,
    config::RC_LOCAL_FILES,
    live::CONNECTIONS,
    live::PROCESSES,
    live::VM_PROCESSES,
    live::VM_LIST,
];

/// A time in a configuration file: `2026-04-04T19:06:39.106766+00:00`.
pub(crate) fn iso_time(input: &Input, text: &str) -> Option<Timestamp> {
    let (parsed, _) = nixcavate_core::time::parse_iso8601(text.trim().as_bytes())?;
    Some(parsed.recorded().unwrap_or_else(|| input.local_time(parsed.secs, parsed.nanos, parsed.precision)))
}
