#!/usr/bin/env python3
"""Writes segb_v1.bin and segb_v2.bin: synthetic SEGB files made from the published layouts
(see the module comment of biome.rs). Payloads are protobuf messages encoded by hand.
Run: python3 generate.py   (writes next to this script)"""
import os
import struct
import zlib

here = os.path.dirname(os.path.abspath(__file__))
T = 720_000_000.0  # Mac absolute time, 2023-10-26T08:00:00Z


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def f_varint(num, v): return varint(num << 3) + varint(v)
def f_bytes(num, b): return varint(num << 3 | 2) + varint(len(b)) + b
def f_str(num, s): return f_bytes(num, s.encode())
def f_double(num, v): return varint(num << 3 | 1) + struct.pack("<d", v)
def f_fixed32(num, v): return varint(num << 3 | 5) + struct.pack("<I", v)


payloads = [
    # App.InFocus-like: bundle id, start time, a nested message with a flag and a label.
    (1, T, f_str(1, "com.apple.Safari") + f_double(2, T) + f_bytes(3, f_varint(1, 1) + f_str(2, "window one"))),
    (1, T + 5.5, f_str(1, "com.example.Notes") + f_double(2, T + 5.5) + f_varint(4, 300)),
    # Repeated field, fixed32 and a binary (non-UTF-8, non-protobuf) blob.
    (1, T + 9, f_str(1, "tag-a") + f_str(1, "tag-b") + f_fixed32(2, 7) + f_bytes(3, b"\xff\xfe\xfd")),
    # Deleted record with an empty payload.
    (3, T + 20, b""),
    # Not a protobuf message at all: reported with a warning, payload kept as hex.
    (1, T + 30, b"\x0b\x01\x02"),
]


def v1():
    out = bytearray(56)
    out[52:56] = b"SEGB"
    for state, t, payload in payloads:
        out += struct.pack("<IIddII", len(payload), state, t, t + 0.25, zlib.crc32(payload), 0)
        out += payload
        out += b"\0" * (-len(out) % 8)
    out += b"\0" * 64  # unused pre-allocated space
    return bytes(out)


def v2():
    body = bytearray()
    trailer = bytearray()
    for state, t, payload in payloads:
        # Real files align entries to 4 bytes and store the trailer from the end backwards.
        body += b"\0" * (-len(body) % 4)
        body += struct.pack("<II", zlib.crc32(payload), 0) + payload
        trailer = struct.pack("<IId", len(body), state, t) + trailer
    header = b"SEGB" + struct.pack("<Id", len(payloads), T) + b"\0" * 16
    return bytes(header + body + trailer)


for name, data in (("segb_v1.bin", v1()), ("segb_v2.bin", v2())):
    with open(os.path.join(here, name), "wb") as f:
        f.write(data)
