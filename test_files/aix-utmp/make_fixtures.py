#!/usr/bin/env python3
"""Writes the synthetic AIX utmp fixtures. Nothing here was produced by AIX.

The layout is NOT hard-coded as offsets: it is computed from the declaration of `struct utmp`
in AIX's <utmp.h>, as quoted by two public sources (see the module comment of
crates/nixcavate-artifacts/src/aix/utmp.rs), by applying natural alignment for the 32-bit
(ILP32) and 64-bit (LP64) PowerPC ABIs. The header has `int __time_t_space` under
`#if !defined(__64BIT__)` so that `ut_time` lands on the same bytes in both. The script
asserts that, and writes the same logical records once per ABI. Integers are big-endian.

    python3 make_fixtures.py          # writes the files next to this script
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# (name, size, alignment) per ABI; arrays have the alignment of their element.
def declaration(abi64):
    time_size = 8 if abi64 else 4
    fields = [
        ("ut_user", 256, 1),
        ("ut_id", 14, 1),
        ("ut_line", 64, 1),
        ("ut_pid", 4, 4),  # pid_t
        ("ut_type", 2, 2),
        ("__time_t_space", 4, 4) if not abi64 else None,
        ("ut_time", time_size, time_size),  # time_t; time64_t on LP64 is 8 as well
        ("e_termination", 2, 2),
        ("e_exit", 2, 2),
        ("ut_host", 256, 1),
        ("__dbl_word_pad", 4, 4),
        ("__reservedA", 8, 4),
        ("__reservedV", 24, 4),
    ]
    return [f for f in fields if f]


def layout(abi64):
    offset, offsets, widest = 0, {}, 1
    for name, size, align in declaration(abi64):
        offset = (offset + align - 1) // align * align
        offsets[name] = offset
        offset += size
        widest = max(widest, align)
    total = (offset + widest - 1) // widest * widest
    return offsets, total


O32, SIZE32 = layout(False)
O64, SIZE64 = layout(True)
assert SIZE32 == SIZE64 == 648, (SIZE32, SIZE64)
# ut_time's low four bytes are at the same place in both ABIs (big-endian).
assert O32["ut_time"] + 4 == O64["ut_time"] + 8
for name in ("ut_user", "ut_id", "ut_line", "ut_pid", "ut_type", "e_termination", "e_exit", "ut_host"):
    assert O32[name] == O64[name], name


def record(abi64, kind, pid, line, user, host, secs, ident="", term=0, status=0, space=0):
    offsets = O64 if abi64 else O32
    r = bytearray(648)
    r[offsets["ut_user"]:offsets["ut_user"] + len(user)] = user.encode()
    r[offsets["ut_id"]:offsets["ut_id"] + len(ident)] = ident.encode()
    r[offsets["ut_line"]:offsets["ut_line"] + len(line)] = line.encode()
    struct.pack_into(">i", r, offsets["ut_pid"], pid)
    struct.pack_into(">h", r, offsets["ut_type"], kind)
    if abi64:
        struct.pack_into(">q", r, offsets["ut_time"], secs)
    else:
        struct.pack_into(">i", r, offsets["__time_t_space"], space)
        struct.pack_into(">i", r, offsets["ut_time"], secs)
    struct.pack_into(">hh", r, offsets["e_termination"], term, status)
    r[offsets["ut_host"]:offsets["ut_host"] + len(host)] = host.encode()
    return bytes(r)


EMPTY, RUN_LVL, BOOT_TIME, OLD_TIME, NEW_TIME, INIT_PROCESS, LOGIN_PROCESS, USER_PROCESS, DEAD_PROCESS = range(9)
T0 = 1_710_032_400  # 2024-03-10T01:00:00Z


def wtmp(abi64, space=0):
    r = lambda *a, **k: record(abi64, *a, **k, space=space)
    return b"".join([
        r(BOOT_TIME, 0, "system boot", "reboot", "", T0),
        r(RUN_LVL, 1, "run-level 2", "runlevel", "", T0 + 20, ident="rc"),
        r(INIT_PROCESS, 3211, "vty0", "", "", T0 + 30, ident="vty0"),
        r(USER_PROCESS, 8913, "pts/1", "alice", "203.0.113.9", T0 + 600, ident="ts/1"),
        r(USER_PROCESS, 8921, "pts/2", "bob", "", T0 + 700, ident="ts/2"),
        r(DEAD_PROCESS, 8913, "pts/1", "", "", T0 + 1200, ident="ts/1", term=0, status=2),
        r(NEW_TIME, 0, "new time", "date", "", T0 + 1300),
        r(DEAD_PROCESS, 8921, "pts/2", "", "", T0 + 1500, ident="ts/2"),
    ])


def failedlogin(abi64):
    r = lambda *a, **k: record(abi64, *a, **k)
    return b"".join([
        r(USER_PROCESS, 7001, "ssh", "admin", "198.51.100.4", T0 + 100, ident="ssh"),
        r(USER_PROCESS, 7002, "pts/3", "root", "198.51.100.4", T0 + 160, ident="ts/3"),
        r(EMPTY, 0, "", "", "", 0),
    ])


def write(name, data):
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(data)


if __name__ == "__main__":
    write("wtmp.ilp32", wtmp(False))
    write("wtmp.lp64", wtmp(True))
    # A 32-bit process that did not clear the spare word before the time.
    write("wtmp.ilp32-dirty-space", wtmp(False, space=0x5A5A5A5A))
    write("failedlogin.lp64", failedlogin(True))
    # The same records with the type at the offset one source's field list implies
    # (pid as 8 bytes at 334, type at 342): the reader must refuse this, not guess.
    alt = bytearray(wtmp(True))
    for i in range(0, len(alt), 648):
        kind = alt[i + O64["ut_type"]:i + O64["ut_type"] + 2]
        alt[i + O64["ut_type"]:i + O64["ut_type"] + 2] = b"\0\0"
        alt[i + 342:i + 344] = kind
    write("wtmp.alt-type-offset", bytes(alt))
    print("ilp32 offsets", O32)
    print("lp64 offsets", O64)
    sys.exit(0)
