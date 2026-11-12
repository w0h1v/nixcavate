# Limitations

What nixcavate does not do, and which parsers have not been checked against real data. Read
this before relying on a parser in a case.

## How each parser was checked

"Real tool" means the output was compared with the reference tool on the same file.
"Real data" means files written by the real software were parsed and checked by eye or by
count. "Synthetic" means fixtures were built from the published format description only: the
parser may be wrong where the description is.

| Checked against | Parsers |
|---|---|
| Real tool | journald (`journalctl -o json`, 1.5 million entries, 0 mismatches), Unified Log (`log show`, 119,650 entries, 99.9% of messages identical), ASL (`syslog -F raw`, 7,537 records), wtmp/btmp/utmp (`utmpdump`, x86-64 and aarch64), lastlog (`lastlog`), dpkg status (`dpkg-query`), rpm database (`rpm -qa`), SSH key fingerprints (`ssh-keygen -l`), ext4/XFS/APFS readers (`find`, `stat`, checksums of every file), E01 (`ewfacquire` images, byte-identical reads), InstallHistory (`plutil`) |
| Real data | syslog, auth.log and secure (Debian 12, Rocky 9), dnf log and history (Rocky 9), apt history, dpkg log, shell and tool histories (bash, zsh, fish, vim, less, MariaDB), cron, at, systemd units, Docker and Podman files, Apache and nginx logs, UAC live response and body file, iptables and nftables, NetworkManager, Chromium and Firefox history, launchd plists, Background Task Management (a real store: 89 of 89 items), install.log |
| Synthetic only | audit.log (auditd cannot run in a container), yum.log, snap, flatpak, anacron timestamps, **KnowledgeC, Biome (SEGB), FSEvents, TCC, quarantine events, Gatekeeper policy, dslocal accounts, known Wi-Fi networks, Safari history and downloads, emond, system extensions, managed preferences, Chromium and Firefox downloads** |

The macOS stores in bold are user-private or root-only. No real copy of them was
used during development, so they are the least certain parsers in the tool. Three carry
specific doubts:

- **Biome.** The SEGB v1 and v2 layouts follow public write-ups. The v2 entry layout
  (alignment, the 8-byte preamble before each protobuf) is the least certain part. If it is
  wrong, payloads show as hex with a warning rather than as wrong text.
- **FSEvents.** Two published tables of flag bits disagree. nixcavate uses the widely used
  community table and always outputs `flags_raw` beside the names.
- **Chromium and Firefox downloads.** No real download rows were available; state names
  follow each project's documentation.

## Not supported

| Area | What | What happens |
|---|---|---|
| Compression | bzip2 rotations (`.bz2`) | The task is skipped and listed in the summary with the file's last-written time |
| Packages | BerkeleyDB rpm database (`/var/lib/rpm/Packages`, RHEL 7 and Amazon Linux 2), SUSE NDB rpm database, zypper history, Alpine apk database | Not read |
| Logons | wtmpdb and lastlog2 (Debian 13, openSUSE Tumbleweed) | Not read |
| Docker | Images kept in the containerd image store (Docker 29 default) | `docker-images` finds nothing; containers and logs still parse |
| systemd | Enablement symlinks (`*.wants/`), timers joined to the service they start | Unit files are parsed one by one |
| Auth events | Auth lines that land in `messages` (Alpine, SUSE) | Parsed as plain syslog, not classified |
| Unified Log | Backtraces; signpost names; state dumps that are not property lists; a few Apple-private value decoders. About 0.1% of log messages and 12% of state dumps differ from `log show` | The entry is kept; the message shows the raw value or a size marker |
| Unified Log | Oversize message data stored in a file other than the entry's own or its neighbour | The message shows `<oversize data in another file>` |
| Unified Log | `log show` leaves out whole files it considers expired (about 15% of the entries in the test archive). The rule it uses was not established | nixcavate outputs every entry that is in the files, so its counts are higher than `log show`'s |
| Disk images | Btrfs, LVM2, LUKS, software RAID, Fusion and multi-device APFS, EWF2 (`.Ex01`) | The partition is named in a warning and skipped |
| APFS | Encrypted (FileVault) and sealed system volumes; LZVN and LZFSE compressed files; reading inside snapshots | Volumes are listed; unreadable files are listed with their size but not read |
| ext4 | Journal replay, deleted-file recovery | The volume is read as it sits on disk |
| Filesystems | Extended attributes (other than ext4 inline data and APFS symlinks and compression) | Not read |
| APFS snapshots | Writing them out as an artifact | The APFS reader lists snapshot names, times and ids; no artifact writes them out yet |
| Collections | Nested archives (CatScale packs logs as tarballs inside the collection) | Extract the inner archives first |
| Windows | Everything | Out of scope |

## Behavior to know

- **Zone-less times depend on the host zone.** If the evidence has neither zone data nor a
  zone name, UTC is assumed. The manifest's `timezone` field says what was used; every such
  timestamp is marked `assumed_zone`.
- **Year inference can be wrong** for a syslog line more than a year older than its file's
  last write. Such timestamps are marked `inferred_year`.
- **File modification times come from the collection.** tar keeps them. Zip stores local
  time with no zone, read as UTC. A plain directory copy may have reset them, which also
  affects year inference. `input_modified` in the manifest shows what was seen.
- **Expansion is limited.** A compressed log or archive that expands more than 100 times is
  cut (`--max-expansion`). The task fails, keeps what it parsed, and the manifest shows the
  span covered.
- **Two hosts with one name** get separate output folders (`name`, `name-2`), but their
  manifest tasks and records carry the same `host` value. Use the output path to tell them
  apart.
- **A mounted volume is walked in full** before parsing, which takes seconds per million
  files.
- **Memory-mapped reads abort on I/O errors.** If evidence on failing media or a network
  share returns an error mid-read, the operating system raises `SIGBUS` and the run stops
  without a manifest. Copy such evidence to local disk first.
- **CSV cells are written as they are.** A cell from evidence that starts with `=`, `+`,
  `-` or `@` is not neutralized, because the output must match the evidence. Do not open
  the CSV in a spreadsheet that evaluates formulas.
- **Persistence-hunter findings are heuristics.** A clean result is not proof of absence.
  In directory mode, file ownership is that of the extracting user, so the
  ownership checks are only meaningful for archives and images.
- **Disk images are bounded.** A volume is listed up to 20 million files, paths up to 4096
  bytes and 256 levels deep; anything beyond is skipped with a warning. A file larger than
  2 GiB, or a sparse file over 64 MiB with less than 1/16 of it allocated, is listed but not
  read.

## Performance targets not met

See [PERFORMANCE.md](PERFORMANCE.md). In short: the timeline target is met; two text parsers
(auth-log, dpkg-log) and the Unified Log parser are below their per-core targets; per-core
throughput is a third to a half lower in `auto-parse`, where every log line also becomes a
timeline event; and a run's wall time is set by its largest unsplittable file.
