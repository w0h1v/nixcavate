#!/usr/bin/env python3
"""Builds `macos-synthetic.audit` and `tokens-synthetic.audit`: BSM records written from the
layouts in audit.log(5) and OpenBSM's audit_record.h, NOT produced by an audit daemon.

A macOS trail cannot be made without root, so macOS-style records (macOS event numbers,
`AUE_sudo`, `AUE_auth_user`, subject_ex with a loopback address) are built here, and so are the
tokens a FreeBSD amd64 kernel never wrote in the real trails (64-bit header, subject, arg,
return and attr tokens, sockets, in_addr, ip, iport, seq, zonename, groups, ipc).
Run: python3 make_synthetic.py   (writes both files next to this script)."""
import struct, os

def tok(i, *parts): return bytes([i]) + b"".join(parts)
def u8(x): return struct.pack(">B", x)
def u16(x): return struct.pack(">H", x)
def u32(x): return struct.pack(">I", x)
def u64(x): return struct.pack(">Q", x)
def s16(text): b = text.encode() + b"\0"; return u16(len(b)) + b

def record(header_id, event, sec, msec, tokens, modifier=0, version=11, ex_addr=None):
    body = b"".join(tokens)
    if header_id in (0x14, 0x15):
        ts = u32(sec) + u32(msec)
    else:
        ts = u64(sec) + u64(msec)
    ex = b""
    if header_id in (0x15, 0x79):
        ex = u32(4) + bytes(ex_addr or (127, 0, 0, 1))
    header_len = 1 + 4 + 1 + 2 + 2 + len(ex) + len(ts)
    total = header_len + len(body) + 7
    header = bytes([header_id]) + u32(total) + u8(version) + u16(event) + u16(modifier) + ex + ts
    trailer = tok(0x13, u16(0xB105), u32(total))
    return header + body + trailer

def subject32(auid, euid, egid, ruid, rgid, pid, sid, port, addr):
    return tok(0x24, *(u32(x) for x in (auid, euid, egid, ruid, rgid, pid, sid, port)), bytes(addr))
def subject32_ex(auid, euid, egid, ruid, rgid, pid, sid, port, addr6):
    return tok(0x7A, *(u32(x) for x in (auid, euid, egid, ruid, rgid, pid, sid, port)), u32(16), bytes(addr6))
def subject64(auid, euid, egid, ruid, rgid, pid, sid, port, addr):
    return tok(0x75, *(u32(x) for x in (auid, euid, egid, ruid, rgid, pid, sid)), u64(port), bytes(addr))
def ret32(status, value): return tok(0x27, u8(status), u32(value))
def ret64(status, value): return tok(0x72, u8(status), u64(value))
def text(t): return tok(0x28, s16(t))
def path(p): return tok(0x23, s16(p))
def exec_args(*args): return tok(0x3C, u32(len(args)), *(a.encode() + b"\0" for a in args))
def arg32(n, v, name): return tok(0x2D, u8(n), u32(v), s16(name))
def arg64(n, v, name): return tok(0x71, u8(n), u64(v), s16(name))

LOOP6 = bytes(15) + b"\x01"

macos = b"".join([
    # AUE_login (6152), subject_ex with ::1: a console login of uid 501.
    record(0x15, 6152, 1_700_000_000, 123, [subject32_ex(501, 501, 20, 501, 20, 310, 100005, 0, LOOP6),
                                              text("successful login alice"), ret32(0, 0)], ex_addr=(127, 0, 0, 1)),
    # AUE_sudo (45028): sudo of `id` by audit user 501 as root.
    record(0x14, 45028, 1_700_000_010, 456, [exec_args("sudo", "id"),
                                              subject32(501, 0, 0, 0, 0, 411, 100005, 16777220, (0, 0, 0, 0)),
                                              ret32(0, 0)]),
    # AUE_auth_user (45023), failed.
    record(0x14, 45023, 1_700_000_020, 9, [subject32(4294967295, 0, 0, 0, 0, 77, 100006, 0, (0, 0, 0, 0)),
                                            text("Authentication failed for mallory"), ret32(1, 1)]),
    # 43201 is AUE_GETATTRLISTBULK on macOS and AUE_WAIT6 on FreeBSD: the host decides the name.
    record(0x14, 43201, 1_700_000_030, 700, [path("/Users/alice/Documents"),
                                              subject32(501, 501, 20, 501, 20, 412, 100005, 0, (0, 0, 0, 0)),
                                              ret32(0, 3)]),
    # AUE_modify_password (45014).
    record(0x14, 45014, 1_700_000_040, 1, [subject32(0, 0, 0, 0, 0, 88, 100007, 0, (0, 0, 0, 0)),
                                            text("modify password for user alice"), ret32(0, 0)]),
])

tokens = b"".join([
    # header64 + subject64 + arg64 + return64 + attr64 + seq + zonename
    record(0x74, 23, 1_700_000_100, 5, [path("/bin/ls"), arg64(1, 0x1122334455667788, "mode"),
                                         subject64(1001, 1001, 1001, 1001, 1001, 900, 800, 0x0000000100000002, (192, 0, 2, 9)),
                                         tok(0x73, u32(0o100755), u32(0), u32(0), u32(65), u64(12345), u64(7)),
                                         tok(0x2F, u32(77)), tok(0x60, s16("global")), ret64(0, 1 << 40)]),
    # header32_ex (IPv4 machine) + sockets and addresses
    record(0x15, 32800, 1_700_000_110, 6, [subject32(1001, 1001, 1001, 1001, 1001, 901, 801, 22, (192, 0, 2, 9)),
                                            tok(0x80, u16(2), u16(443), bytes((198, 51, 100, 5))),
                                            tok(0x81, u16(28), u16(8080), LOOP6),
                                            tok(0x7F, u16(2), u16(1), u16(4), u16(1234), bytes((10, 0, 0, 1)), u16(4), u16(80), bytes((10, 0, 0, 2))),
                                            tok(0x2A, bytes((203, 0, 113, 1))), tok(0x2C, u16(8443)),
                                            tok(0x2B, bytes(20)), tok(0x34, u16(2), u32(0), u32(5)),
                                            tok(0x22, u8(1), u32(55)), tok(0x82, u16(1), b"/tmp/example.sock\0"), ret32(0, 0)], ex_addr=(10, 1, 1, 1)),
    # header64_ex
    record(0x79, 6152, 1_700_000_120, 7, [text("header64_ex record"), ret32(0, 0)], ex_addr=(10, 2, 2, 2)),
    # process tokens (the target of a signal), subject64_ex, the old socket token, in_addr_ex, cmd, ipc_perm, opaque, host
    record(0x14, 15, 1_700_000_130, 8, [
        tok(0x26, *(u32(x) for x in (1001, 0, 0, 0, 0, 4242, 4000, 0)), bytes((10, 0, 0, 5))),
        tok(0x77, *(u32(x) for x in (1002, 0, 0, 0, 0, 4243, 4001)), u64(5), bytes((10, 0, 0, 6))),
        tok(0x7B, *(u32(x) for x in (1003, 0, 0, 0, 0, 4244, 4002, 0)), u32(4), bytes((10, 0, 0, 7))),
        tok(0x7D, *(u32(x) for x in (1004, 0, 0, 0, 0, 4245, 4003)), u64(0), u32(16), LOOP6),
        tok(0x7C, *(u32(x) for x in (2001, 2002, 2003, 2004, 2005, 5000, 5001)), u64(22), u32(4), bytes((192, 0, 2, 20))),
        tok(0x2E, u16(2), u16(80), bytes((192, 0, 2, 1)), u16(1024), bytes((192, 0, 2, 2))),
        tok(0x7E, u32(16), LOOP6),
        tok(0x51, u16(2), s16("ls"), s16("-l"), u16(1), s16("HOME=/root")),
        tok(0x32, *(u32(x) for x in (1, 2, 3, 4, 0o644, 6, 7))),
        tok(0x29, u16(3), b"abc"),
        tok(0x70, bytes((172, 16, 0, 1))),
        ret32(0, 0)]),
])

here = os.path.dirname(os.path.abspath(__file__))
open(os.path.join(here, "macos-synthetic.audit"), "wb").write(macos)
open(os.path.join(here, "tokens-synthetic.audit"), "wb").write(tokens)
print(len(macos), len(tokens))
