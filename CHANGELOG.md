# Changelog

Every change to the output contract ([docs/OUTPUT.md](docs/OUTPUT.md)) is listed here:
field names, file layout, manifest schema, exit codes.

## 0.1.0 (unreleased)

First version.

- Commands: `auto-parse`, `parse`, `super-timeline`, `persistence-hunter`, `list`.
- Inputs: directories, `.tar`, `.tar.gz`, `.tar.zst`, `.tar.xz`, `.zip`, raw and E01 disk
  images (ext4, XFS, APFS).
- Manifest `schema_version` 1.
- Timeline run file format version 2 (sorted events plus a sparse index).
