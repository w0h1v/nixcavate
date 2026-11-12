#!/usr/bin/env python3
"""Writes sample.asl, a synthetic Apple System Log database (version 2).

Follows the published layout (libyal dtformats, "Apple System Log (ASL) file format"), big-endian:
header of 80 bytes; string records (u16 type=1, u32 length incl. NUL, text); records (u16, u32
length of the rest, u64 next offset, u64 id, i64 secs, u32 nanos, u16 level, u16 flags, u32 pid,
uid, gid, read-uid, read-gid, ref-pid, item count, six string refs, key/value refs, u64 previous
offset). Strings up to 7 bytes are inline (top bit set, low 7 bits of the first byte = length).
All names and values are invented. Usage: python3 generate.py [output-path]
"""
import struct
import sys

out = bytearray(b"ASL DB\0\0\0\0\0\0" + struct.pack(">I", 2) + bytes(64))
strings = {}


def ref(text):
    if text == "":
        return 0
    raw = text.encode()
    if len(raw) <= 7:
        return (0x80 | len(raw)) << 56 | int.from_bytes(raw.ljust(7, b"\0"), "big")
    if text not in strings:
        strings[text] = len(out)
        out.extend(struct.pack(">HI", 1, len(raw) + 1) + raw + b"\0")
    return strings[text]


records = [
    dict(id=1, secs=1710032523, nanos=123456789, level=5, pid=412, uid=0, gid=0, rgid=80,
         host="mac01", sender="syslogd", fac="com.apple.asl.statistics", msg="ASL Sender Statistics",
         extra=[("MsgCount", "16"), ("*sshd", "3 1200")]),
    dict(id=2, secs=1710032600, nanos=0, level=3, pid=777, uid=501, gid=20, ruid=501,
         host="mac01.example.com", sender="sshd", fac="com.apple.system", msg="Failed password for alice from 192.0.2.10",
         refpid=1, refproc="launchd", session="100001", extra=[("Facility", "auth"), ("Empty", "")]),
    dict(id=3, secs=1710032700, nanos=5, level=9, pid=-2, uid=-2, gid=-2, host="", sender="", fac="", msg="", extra=[]),
]
# Strings first, so record offsets are known while writing.
for r in records:
    for key in ("host", "sender", "fac", "msg", "refproc", "session"):
        ref(r.get(key, ""))
    for k, v in r["extra"]:
        ref(k), ref(v)
first = len(out)
previous = 0
offsets = []
for i, r in enumerate(records):
    offsets.append(len(out))
    items = [x for kv in r["extra"] for x in kv]
    rest = 8 + 8 + 8 + 4 + 2 + 2 + 4 * 7 + 8 * 6 + 8 * len(items) + 8
    size = 6 + rest
    nxt = len(out) + size if i + 1 < len(records) else 0
    body = struct.pack(">HIQQqIHH", 0, rest, nxt, r["id"], r["secs"], r["nanos"], r["level"], 2)
    body += struct.pack(">IIIIII", *(x & 0xFFFFFFFF for x in (r["pid"], r["uid"], r["gid"], r.get("ruid", -1), r.get("rgid", -1), r.get("refpid", 0))))
    body += struct.pack(">I", len(items))
    body += b"".join(struct.pack(">Q", ref(r.get(k, ""))) for k in ("host", "sender", "fac", "msg", "refproc", "session"))
    body += b"".join(struct.pack(">Q", ref(x)) for x in items)
    body += struct.pack(">Q", previous)
    assert len(body) == size
    previous = len(out)
    out.extend(body)
struct.pack_into(">QQIQ", out, 16, first, 1710032000, len(out) - 80, previous)
open(sys.argv[1] if len(sys.argv) > 1 else "sample.asl", "wb").write(out)
