# Changelog

Every change to the output contract ([docs/OUTPUT.md](docs/OUTPUT.md)) is listed here:
field names, file layout, manifest schema, exit codes.

## 0.1.0 (unreleased)

First version.

- Commands: `auto-parse`, `parse`, `super-timeline`, `persistence-hunter`, `list`.
- Inputs: directories, `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.zst`, `.tar.xz`, `.zip`, raw and E01 disk
  images (ext4, XFS, APFS).
- `super-timeline --start` and `--end` limit the timeline to a time window.
- bzip2: `.bz2` log rotations and `.tar.bz2` archives are read.
- `rpm-db` reads the BerkeleyDB hash database (`/var/lib/rpm/Packages`, RHEL 7 and
  Amazon Linux 2, either byte order) as well as SQLite.
- Biome SEGB v2: entries start on a 4-byte boundary, found by checking real files.
- Manifest `schema_version` 1.
- Timeline run file format version 2 (sorted events plus a sparse index).
