# nixcavate

[![ci](https://github.com/w0h1v/nixcavate/actions/workflows/ci.yml/badge.svg)](https://github.com/w0h1v/nixcavate/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)](LICENSE)

A fast, single-binary forensic artifact parser for Linux and macOS collections, which also reads
FreeBSD, OpenBSD, NetBSD, Solaris/illumos, VMware ESXi and IBM AIX hosts.
Overview and benchmarks: <https://w0h1v.github.io/nixcavate/>

nixcavate turns a collected host (a UAC, Velociraptor or Aftermath collection, a mounted
volume, or a disk image) into per-artifact CSV, JSON or JSONL, a task manifest and a super
timeline. It needs no runtime, no root and no network.

It does not run Sigma rules. It imports the results of ChopChopGo or Zircolite into its
timeline instead.

## Quick start

```sh
cargo build --release                    # the binary is target/release/nixcavate

# Parse everything in a collection
nixcavate auto-parse -f uac-web01-linux-20260101.tar.gz -o out

# Build the timeline from that run, with Sigma detections merged in
nixcavate super-timeline -d out --sigma chopchopgo.json
nixcavate super-timeline -d out --start 2026-03-01 --end 2026-03-08

# Look for persistence, mapped to ATT&CK
nixcavate persistence-hunter -f uac-web01-linux-20260101.tar.gz -o findings.csv

# One parser on one file
nixcavate parse wtmp -f /cases/web01/wtmp -t jsonl

# What can it parse, and where does it look?
nixcavate list
```

## Commands

| Command | Purpose |
|---|---|
| `auto-parse` | Find each host in the evidence, run every parser, write per-host results and `manifest.json` |
| `parse <artifact>` | Run one parser on one file (`-f`) or on every match in a directory or archive (`-d`) |
| `super-timeline` | Merge the timeline events of a parsed run, and imported Sigma results, into one sorted file |
| `persistence-hunter` | Run persistence checks mapped to ATT&CK, with a YAML allow/block profile |
| `list` | Show every artifact, its OS, its category and the paths it reads |

Shared options: `-d` directory, `-f` file, `-o` output, `-t csv|json|jsonl`, `-T` threads,
`-C` replace an earlier run, `-q` quiet, `-K` no color. `auto-parse` also takes
`--only` and `--skip` with artifact ids. `--max-expansion` bounds how far compressed
evidence may expand (a guard against decompression bombs). Every command has `--help`.

## Inputs

| Input | Notes |
|---|---|
| Directory | An extracted collection, a mounted volume, or a folder of collections and archives, up to three levels down (each becomes a host) |
| Collector output | UAC, CatScale, CyLR, Velociraptor and fastir collections, and plain archives of a root filesystem, as they come |
| `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.zst`, `.tar.xz`, `.zip` | Read in place; nothing is extracted |
| Raw (also split into `.001`, `.002`...) and E01 disk images | GPT and MBR partitions, BSD disklabels and Solaris VTOCs, linear LVM2 volumes and Linux software RAID arrays (also one image per member disk, found beside the evidence file) with ext2/3/4, XFS, Btrfs, APFS, UFS (FreeBSD, NetBSD, OpenBSD and Solaris UFS1/UFS2, either byte order) or ZFS (FreeBSD and illumos pools; a pool whose mirror, stripe or RAID-Z members are partitions of the same image is assembled, and shown with its datasets where the system mounts them). The volumes of one disk that the root's `/etc/fstab` mounts (`/boot`, `/var`, `/home`...) are one host. The file timeline comes from the filesystem itself |
| qcow2, VMDK, VHD, VHDX and VDI virtual machine disks | Read directly, no conversion; the same partitions and filesystems. Snapshots, linked clones, backing files and encrypted disks are refused with the reason (see [docs/LIMITATIONS.md](docs/LIMITATIONS.md)) |

Hosts are discovered by layout (`[root]/` in UAC, `/etc` and `/var/log` on Linux,
`/private/var` and `/System` on macOS), so no flag says what kind of collection it is.

## Output

```
out/
  manifest.json                              one entry per task: status, time, records, warnings
  web01/
    Accounts/wtmp/var_log_wtmp.csv           records, one file per input
    Logs/auth-log/var_log_auth.log.csv
    _timeline/...                            sorted runs for super-timeline
  timeline.csv                               written by super-timeline
```

Every row carries `host`, `artifact`, `source_path` and `source_line` or `source_offset`.
Every timestamp is UTC, and every timeline row says how precise its time is and whether it
was recorded, had its zone assumed, or had its year inferred. Exit code 0 means every task
succeeded or was skipped, 1 means some task failed, 2 means the run could not start.
[docs/OUTPUT.md](docs/OUTPUT.md) is the full contract.

## Artifacts

`nixcavate list` prints the authoritative table with paths. In summary:

| Area | Linux | macOS |
|---|---|---|
| Accounts and logons | passwd, shadow (hash type only), group, sudoers, wtmp, btmp, utmp, lastlog, wtmpdb, lastlog2, failed-login counters (`faillock`, `tallylog`, `faillog`), password history (`opasswd`: algorithms only), SSH logons from `auth.log`, `secure` and `messages` | local accounts (dslocal) |
| Logs | journald, syslog, audit, Apache and nginx; mail (Postfix, Dovecot, Exim), PostgreSQL, MySQL and MariaDB, HAProxy, Squid, BIND, fail2ban, FTP, Samba, ModSecurity, Tomcat | Unified Log, ASL, `system.log`, `install.log` |
| Execution and activity | bash, zsh, fish, Python, MySQL, less and Vim histories, and those of node, psql, sqlite3, redis-cli, irb, PHP, gdb, mongo and PowerShell; process accounting (`pacct`), systemd coredumps, apport and ABRT crash reports, kernel crash dumps, sudo I/O logs, log files and authentication cache, sysstat history; Chromium and Firefox (history, downloads, cookies, saved-login metadata, extensions, sessions); GTK recent files, the trash, thumbnails, CUPS print jobs | the same histories (also per-session); Safari, KnowledgeC, Biome, FSEvents, power log, crash reports, Rosetta translation cache, execution policy (`ExecPolicy`), recent items and Finder/Dock/Spotlight state, Messages, Mail envelopes, call history |
| Persistence | cron, anacron, at, systemd units with their enablement links and timers, `rc.local`, `init.d`, shell profiles, `ld.so.preload`, `authorized_keys`, udev, kernel modules, PAM, XDG autostart, MOTD, NetworkManager dispatcher and logrotate scripts, `pam_env`, sshd key commands | LaunchAgents and LaunchDaemons, Background Task Management, emond, kernel and system extensions, managed preferences, cron and periodic, login and logout hooks, StartupItems, `rc.local`, Folder Actions, authorization and other plug-in bundles, configuration profiles |
| Software | dpkg, apt, `update-alternatives`, yum (log, history, yumdb), dnf, dnf5, rpm (SQLite, BerkeleyDB and SUSE ndb), zypper, pacman (log and database), apk, emerge and the portage database, xbps, tdnf, snap, flatpak | InstallHistory, package receipts |
| Network | hosts, resolv.conf, NetworkManager, SSH known hosts and config, iptables, nftables, DHCP leases, Remmina and FileZilla servers, USB devices from kernel logs | known Wi-Fi networks, SSH, per-process network usage, DHCP leases, interfaces, URL caches, cookie metadata, HSTS, Bluetooth |
| Security | | TCC, quarantine events, Gatekeeper policy, XProtect version, `auth.db`, application firewall, iOS pairing records (identifiers only) |
| Containers | Docker, Podman, runtime configs | |
| Kubernetes | pod and container logs (CRI and Docker formats), static pod and k3s auto-applied manifests, kubelet configuration, kubeconfig files (names, never credentials), CNI configuration, API audit log, containerd containers and sandboxes | |
| Cloud agents | AWS SSM agent logs and Run Command and Session Manager files, Azure Linux agent log, extension settings and `ovf-env.xml`; credential files of cloud and developer tools (names, never secrets) | |
| Remote access | AnyDesk, TeamViewer, RustDesk, MeshAgent, VS Code server and tunnels, ngrok, cloudflared, Tailscale, ZeroTier, frp, WireGuard and OpenVPN: configuration, logs and connection lists | |
| Filesystem and live data | UAC body file and live response (processes, sockets, open files, modules); file timeline from disk images | file timeline from APFS images |

VMware ESXi hosts (a `vm-support` bundle, a UAC collection made with its `esxi` profile, or copies of
`/var/log` and `/etc/vmware`) are recognised as a separate system: shell commands (`shell.log`),
`hostd` logins and VM power operations, VOB events, VMkernel warnings, `sshd` logins, per-VM logs, VIBs,
`esx.conf`, registered VMs, permissions, firewall rule sets, `rc.local.d` and the saved `esxcli` command output;
`persistence-hunter` judges `local.sh`, community VIBs, extra administrators and the SSH switch.

IBM AIX hosts (a UAC collection, or copies of `/etc` and `/var/adm`) get their own artifacts: the
big-endian `wtmp`, `utmp` and `failedlogin` records, `lastlog`, `sulog`, the cron log, the
`etc/security` stanza files, `inittab`, `rc` scripts, `inetd.conf`, `.rhosts`, `.sh_history`,
SMIT logs, and the output of `errpt`, `lslpp`, `netstat`, `lssrc` and `genkex`. No AIX system was
available, so every AIX parser is checked against documentation and a few public samples only; see
[docs/LIMITATIONS.md](docs/LIMITATIONS.md) before relying on one.

FreeBSD, OpenBSD and NetBSD hosts (from a UAC collection, a plain tar of the root, a mounted
folder, or a disk image with UFS/FFS or, on FreeBSD, ZFS) are read for logins (`utx`, `wtmp`, `utmpx`, `lastlog`), BSM
audit trails (`bsm-audit`, also macOS), packages (`pkg`, `pkg_add`, pkgsrc), the shared syslog,
auth, cron, sudoers and shell files, and the BSD boot and service files (`rc.conf`, `rc.d`, `rc.local`,
`loader.conf`, `ttys`, `doas.conf`, `devd`, jails, `master.passwd`), with 15 persistence checks.

Solaris and illumos hosts (OmniOS verified; Oracle Solaris from documentation) are read for login
records, BSM audit trails, the SMF repository, IPS and SVR4 packages, RBAC, cron and `at`, from a
collection or from a disk image with UFS or ZFS.

What is not supported, and what has only been checked against synthetic data, is listed in
[docs/LIMITATIONS.md](docs/LIMITATIONS.md). Read it before relying on a parser in a case.

## Speed

Speed is the main feature. On a 12-core laptop a 900 MiB synthetic Linux host
parses in about 0.7 s, a 2.9 GiB one with an 880 MiB journal in 3.3 s, and a real 826 MiB
macOS Unified Log archive (26 million entries) in 4.5 s. The timeline step takes about a
fifth of the parse time. [docs/PERFORMANCE.md](docs/PERFORMANCE.md) has the numbers, how they were measured
and where the targets are not met.

## Safety

Evidence is treated as hostile. Paths from evidence are never used as paths on the analyst's
machine, symlinks are never followed out of the evidence, special files are never opened,
sizes inside archives and compressed files are budgeted, and a parser failure costs one task,
not the run. Shadow hashes, Wi-Fi keys and password verifiers are never written out.
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#hostile-input).

## Development

```sh
cargo test --workspace                   # unit, snapshot and end-to-end tests
cargo clippy --workspace --all-targets
cargo deny check                         # licenses and advisories
fuzz/run.sh 30                           # every fuzz target for 30 s (nightly, cargo-fuzz)
python3 bench/bench.py <name> <corpus>   # throughput and record-count gate
```

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How a run works and why it is fast |
| [docs/OUTPUT.md](docs/OUTPUT.md) | The output contract: layout, fields, manifest, exit codes |
| [docs/ADDING_AN_ARTIFACT.md](docs/ADDING_AN_ARTIFACT.md) | How to write a parser |
| [docs/PERSISTENCE_HUNTER.md](docs/PERSISTENCE_HUNTER.md) | The checks, their ATT&CK mapping and the profile format |
| [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | Measured numbers against the design targets |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | Unsupported formats and unverified parsers |
| [bench/README.md](bench/README.md) | The benchmark corpus and the regression gate |

Parsers are written clean-room from published format documentation and test data.

## License

MIT. See [LICENSE](LICENSE).
