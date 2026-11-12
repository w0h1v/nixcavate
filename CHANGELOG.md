# Changelog

Every change to the output contract ([docs/OUTPUT.md](docs/OUTPUT.md)) is listed here:
field names, file layout, manifest schema, exit codes.

## 0.1.0 (unreleased)

First version.

- Commands: `auto-parse`, `parse`, `super-timeline`, `persistence-hunter`, `list`.
- Inputs: directories, `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.zst`, `.tar.xz`, `.zip`, raw and E01 disk
  images (ext4, XFS, APFS).
- NUL padding at the start of a log line is skipped, so the line after it is parsed.
- `dnf-log`: scriptlet output lines take the time of the line before them.
- `web-error-log`: a line in no server format is kept as a message with no time.
- `syslog` also reads `var/log/ufw.log*`.
- `auth-log` also reads `var/log/messages*` and outputs the lines there that are auth events
  (Alpine, SUSE). The `syslog` artifact still outputs every line of that file.
- New artifacts: `wtmpdb` and `lastlog2` (the SQLite login records of Debian 13 and openSUSE
  Tumbleweed), `dnf5-log` (Fedora).
- `lastlog` and `utmp`: the aarch64 record layout is recognized from the file length, so a
  file with one record is read correctly.
- `live-open-files` reads BusyBox `lsof` output (Alpine).
- The host's OS version falls back to `system-release`, `lsb-release`, `debian_version` and
  `alpine-release` when `os-release` was not collected.
- LVM2: linear logical volumes in disk images are read and listed as `<vg>-<lv>` (see [docs/LIMITATIONS.md](docs/LIMITATIONS.md)).
- `super-timeline --start` and `--end` limit the timeline to a time window.
- bzip2: `.bz2` log rotations and `.tar.bz2` archives are read.
- `rpm-db` reads the BerkeleyDB hash database (`/var/lib/rpm/Packages`, RHEL 7 and
  Amazon Linux 2, either byte order) as well as SQLite.
- Biome SEGB v2: entries start on a 4-byte boundary, found by checking real files.
- Manifest `schema_version` 1.
- Timeline run file format version 2 (sorted events plus a sparse index).
