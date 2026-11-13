#!/usr/bin/env python3
"""Builds synthetic .DS_Store files from the documented buddy-allocator and B-tree layout
(big-endian, addresses relative to byte 4). Example names only. Run: python3 generate.py"""
import os, struct

here = os.path.dirname(os.path.abspath(__file__))


def ustr(s):
    return struct.pack(">I", len(s)) + s.encode("utf-16-be")


def record(name, code, typ, value):
    out = ustr(name) + code.encode() + typ.encode()
    if typ == "bool":
        out += bytes([1 if value else 0])
    elif typ in ("long", "shor"):
        out += struct.pack(">I", value)
    elif typ == "ustr":
        out += ustr(value)
    elif typ == "blob":
        out += struct.pack(">I", len(value)) + value
    elif typ in ("comp", "dutc"):
        out += struct.pack(">Q", value)
    elif typ == "type":
        out += value.encode()
    return out


def leaf(records):
    return struct.pack(">II", 0, len(records)) + b"".join(records)


def internal(children, records, rightmost):
    out = struct.pack(">II", rightmost, len(records))
    for child, rec in zip(children, records):
        out += struct.pack(">I", child) + rec
    return out


def build(nodes, root_id, levels):
    """nodes: {block id: bytes}. Blocks 1 is DSDB; node ids start at 2."""
    size = 4 + 0x1800 + 0x800 + 0x1000 * len(nodes)
    f = bytearray(size)
    f[0:4] = struct.pack(">I", 1)
    f[4:8] = b"Bud1"
    root_off, root_size = 0x1000, 0x800
    f[8:20] = struct.pack(">III", root_off, root_size, root_off)
    addrs = [root_off | 11, 0x20 | 5]  # block 0: root info, block 1: DSDB
    base = 0x1800
    for i, (nid, data) in enumerate(sorted(nodes.items())):
        assert nid == len(addrs)
        off = base + 0x1000 * i
        addrs.append(off | 12)
        f[4 + off:4 + off + len(data)] = data
    f[4 + 0x20:4 + 0x20 + 20] = struct.pack(">IIIII", root_id, levels, 0, len(nodes), 0x1000)
    root = struct.pack(">II", len(addrs), 0)
    root += b"".join(struct.pack(">I", a) for a in addrs) + b"\0" * (4 * (256 - len(addrs)))
    root += struct.pack(">I", 1) + bytes([4]) + b"DSDB" + struct.pack(">I", 1)
    root += struct.pack(">I", 0) * 32
    f[4 + root_off:4 + root_off + len(root)] = root
    return bytes(f)


# 1904-based fixed point seconds: 2023-11-14T22:13:20Z
hfs = (1_700_000_000 + 2_082_844_800) << 16
recs = [
    record(".", "vSrn", "long", 1),
    record("deleted-plan.txt", "ptbL", "ustr", "Users/alice/Documents"),
    record("deleted-plan.txt", "ptbN", "ustr", "deleted-plan.txt"),
    record("notes.txt", "Iloc", "blob", struct.pack(">II", 100, 200) + b"\xff" * 8),
    record("notes.txt", "modD", "dutc", hfs),
    record("notes.txt", "dilc", "bool", True),
    record("notes.txt", "lsvp", "blob", b"bplist00-view-settings-not-decoded"),
    record("secret.pdf", "cmmt", "ustr", "café comment"),
]
with open(os.path.join(here, "Synthetic_DS_Store"), "wb") as f:
    f.write(build({2: leaf(recs)}, 2, 0))

# Two levels: an internal node (id 4) with one record and two leaf children (ids 2, 3).
left = leaf([record("aaa", "Iloc", "blob", b"x" * 16)])
right = leaf([record("ccc", "Iloc", "blob", b"x" * 16), record("ddd", "Iloc", "blob", b"x" * 16)])
top = internal([2], [record("bbb", "Iloc", "blob", b"x" * 16)], 3)
with open(os.path.join(here, "Tree_DS_Store"), "wb") as f:
    f.write(build({2: left, 3: right, 4: top}, 4, 1))
