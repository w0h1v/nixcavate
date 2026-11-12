#!/usr/bin/env python3
"""Writes v1.gz and v2.gz, synthetic FSEvents (.fseventsd) page streams.

Layout (libyal dtformats, "MacOS File System Events Disk Log Stream format"), little-endian:
page = magic "1SLD"/"2SLD", 4 unknown bytes, u32 page size (header included), then records:
NUL-terminated path, u64 event id, u32 flags, and for version 2 a u64 node id. Flag bits are the
community table used by the FSEvents parsers (see fsevents.rs). Paths are invented.
Usage: python3 generate.py [output-dir]
"""
import gzip
import struct
import sys
from pathlib import Path

FOLDER, MOUNT, FILE_EVENT, CREATED, REMOVED, RENAMED, MODIFIED, FOLDER_CREATED = (
    0x1, 0x2, 0x8000, 0x1000000, 0x2000000, 0x8000000, 0x10000000, 0x80000000)


def record(version, path, event_id, flags, node):
    out = path.encode() + b"\0" + struct.pack("<QI", event_id, flags)
    return out + struct.pack("<Q", node) if version >= 2 else out


def page(version, records, tail=b""):
    body = b"".join(records) + tail
    return f"{version}SLD".encode() + bytes(4) + struct.pack("<I", 12 + len(body)) + body


def build(version, tail):
    v = version
    first = page(v, [
        record(v, "/Users/alice/Documents/report.txt", 1000, FILE_EVENT | CREATED, 11),
        record(v, "/Users/alice/Documents", 1001, FOLDER | FOLDER_CREATED | MODIFIED, 12),
        record(v, "/Volumes/Backup", 1002, FOLDER | MOUNT, 13),
        record(v, "/private/tmp/café.log", 1003, FILE_EVENT | RENAMED | 0x40, 14),
    ])
    second = page(v, [
        record(v, "/Users/bob/notes.md", 2000, FILE_EVENT | REMOVED, 21),
        record(v, "/Users/bob/link", 2001, 0x4000 | 0x1000 | 0x800, 22),
    ], tail)
    return first + second


out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
for version in (1, 2):
    # The v2 file ends in a record cut off after its path and event id; v1 ends cleanly.
    tail = b"/Users/bob/cut.txt\0" + struct.pack("<Q", 2002) if version == 2 else b""
    (out / f"v{version}.gz").write_bytes(gzip.compress(build(version, tail), mtime=0))
