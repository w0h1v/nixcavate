"""Synthetic journal entries.

python3 export.py           the fixture entries, in the journal export format, on stdout
python3 export.py feed N    N generated entries sent to the local journald (benchmarks)
"""
import struct
import sys

BOOT = "4f1c8d2e9a7b4c3d8e2f1a0b9c8d7e6f"
MACHINE = "0123456789abcdef0123456789abcdef"
BASE = 1700000000000000  # 2023-11-14T22:13:20Z in microseconds


def field(out, name, value):
    if isinstance(value, str):
        value = value.encode()
    if b"\n" in value or any(b < 0x20 and b != 0x09 for b in value) or b"\xff" in value:
        out += name.encode() + b"\n" + struct.pack("<Q", len(value)) + value + b"\n"
    else:
        out += name.encode() + b"=" + value + b"\n"


def entry(out, n, fields):
    field(out, "__REALTIME_TIMESTAMP", str(BASE + n * 1_000_123))
    field(out, "__MONOTONIC_TIMESTAMP", str(5_000_000 + n * 1_000_123))
    field(out, "_BOOT_ID", BOOT)
    field(out, "_MACHINE_ID", MACHINE)
    field(out, "_HOSTNAME", "web01.example.com")
    for name, value in fields:
        field(out, name, value)
    out += b"\n"


def fixture(out):
    sshd = [("_TRANSPORT", "syslog"), ("SYSLOG_FACILITY", "4"), ("SYSLOG_IDENTIFIER", "sshd"),
            ("_COMM", "sshd"), ("_EXE", "/usr/sbin/sshd"), ("_SYSTEMD_UNIT", "ssh.service"),
            ("_UID", "0"), ("_GID", "0")]
    entry(out, 0, [("_TRANSPORT", "kernel"), ("PRIORITY", "6"), ("SYSLOG_IDENTIFIER", "kernel"),
                   ("MESSAGE", "Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org)")])
    entry(out, 1, sshd + [("_PID", "812"), ("PRIORITY", "6"),
                          ("_CMDLINE", "sshd: alice [priv]"),
                          ("MESSAGE", "Accepted publickey for alice from 203.0.113.9 port 50122 ssh2")])
    entry(out, 2, sshd + [("_PID", "815"), ("PRIORITY", "5"),
                          ("MESSAGE", "Failed password for invalid user admin from 198.51.100.4 port 4242 ssh2")])
    # No SYSLOG_IDENTIFIER: program falls back to _COMM; unit falls back to UNIT.
    entry(out, 3, [("_TRANSPORT", "journal"), ("PRIORITY", "6"), ("_PID", "1"), ("_UID", "0"),
                   ("_COMM", "systemd"), ("UNIT", "cron.service"), ("CODE_FILE", "src/core/unit.c"),
                   ("MESSAGE", "Started cron.service - Regular background program processing daemon.")])
    # A large, compressible value and a large message.
    big = "".join("line %04d: GET /index.html 200 from 192.0.2.%d\n" % (i, i % 250) for i in range(40))
    entry(out, 4, [("_TRANSPORT", "stdout"), ("PRIORITY", "6"), ("SYSLOG_IDENTIFIER", "nginx"),
                   ("_PID", "2201"), ("_UID", "33"), ("_SYSTEMD_UNIT", "nginx.service"),
                   ("MESSAGE", "access burst:\n" + big), ("DUMP", "x" * 2000)])
    # Binary values, a repeated field and an '=' inside a value.
    entry(out, 5, [("_TRANSPORT", "journal"), ("PRIORITY", "3"), ("SYSLOG_IDENTIFIER", "backup"),
                   ("_PID", "3100"), ("_UID", "1000"), ("_SYSTEMD_USER_UNIT", "backup.service"),
                   ("MESSAGE", b"bad bytes \xff\xfe in path /home/alice/\x01x"),
                   ("BLOB", bytes(range(256)) * 3), ("TAG", "one"), ("TAG", "two"),
                   ("ARG", "key=value=more")])
    # Repeats of shared values (deduplicated DATA objects).
    for n in range(6, 10):
        entry(out, n, sshd + [("_PID", str(900 + n)), ("PRIORITY", "6"),
                              ("MESSAGE", "Accepted publickey for alice from 203.0.113.9 port 50122 ssh2")])


def feed(count):
    """Sends generated entries straight to a running journald over its native socket."""
    import socket
    import time
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    units = ["ssh", "cron", "nginx", "systemd-logind", "docker"]
    for n in range(count):
        prog = units[n % len(units)]
        msg = ("PRIORITY=%d\nSYSLOG_IDENTIFIER=%s\nSYSLOG_FACILITY=3\nCODE_FILE=src/%s.c\nCODE_LINE=%d\n"
               "REMOTE_ADDR=192.0.2.%d\nUSER=alice\nMESSAGE=request %d from 192.0.2.%d user alice status %d bytes %d\n"
               % (n % 8, prog, prog, n % 900, n % 250, n, n % 250, 200 + n % 5, (n * 7919) % 100000)).encode()
        while True:
            try:
                sock.sendto(msg, "/run/systemd/journal/socket")
                break
            except OSError:
                time.sleep(0.001)


if len(sys.argv) > 2 and sys.argv[1] == "feed":
    feed(int(sys.argv[2]))
else:
    out = bytearray()
    fixture(out)
    sys.stdout.buffer.write(out)
