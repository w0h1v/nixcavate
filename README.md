# nixcavate

[![ci](https://github.com/w0h1v/nixcavate/actions/workflows/ci.yml/badge.svg)](https://github.com/w0h1v/nixcavate/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)](LICENSE)

A fast, single-binary forensic artifact parser for Linux and macOS collections.
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
| Directory | An extracted collection, a mounted volume, or a folder of collections and archives (each becomes a host) |
| `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.zst`, `.tar.xz`, `.zip` | Read in place; nothing is extracted |
| Raw and E01 disk images | GPT and MBR partitions with ext2/3/4, XFS or APFS. The file timeline comes from the filesystem itself |

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
| Accounts and logons | passwd, shadow (hash type only), group, sudoers, wtmp, btmp, utmp, lastlog, SSH logons from `auth.log` and `secure` | local accounts (dslocal) |
| Logs | journald, syslog, audit, Apache and nginx | Unified Log, ASL, `system.log`, `install.log` |
| Execution and activity | bash, zsh, fish, Python, MySQL, less and Vim histories; Chromium and Firefox | the same histories; Safari, KnowledgeC, Biome, FSEvents |
| Persistence | cron, anacron, at, systemd units, `rc.local`, `init.d`, shell profiles, `ld.so.preload`, `authorized_keys`, udev, kernel modules, PAM, XDG autostart | LaunchAgents and LaunchDaemons, Background Task Management, emond, kernel and system extensions, managed preferences, cron and periodic |
| Software | dpkg, apt, yum, dnf, rpm (SQLite and BerkeleyDB), snap, flatpak | InstallHistory |
| Network | hosts, resolv.conf, NetworkManager, SSH known hosts and config, iptables, nftables | known Wi-Fi networks, SSH |
| Security | | TCC, quarantine events, Gatekeeper policy, XProtect version |
| Containers | Docker, Podman, runtime configs | |
| Filesystem and live data | UAC body file and live response (processes, sockets, open files, modules); file timeline from disk images | file timeline from APFS images |

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
