#!/usr/bin/env python3
"""Writes a synthetic ksh history file in the layout of ksh93's history.c (public source):
0x81 and a version byte first; each command NUL-terminated and starting on an even byte; the
pair 0x81 0x00 cancels the previous command; a six-byte marker (0x82, 0, three bytes of command
number, 0) records the command number. Nothing here came from an AIX host.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def marker(number):
    return bytes([0x82, 0, (number >> 16) & 0xFF, (number >> 8) & 0xFF, number & 0xFF, 0])


def command(text):
    data = text.encode() + b"\0"
    return data + (b"\0" if len(data) % 2 else b"")


body = bytearray(b"\x81\x01")
for n, text in enumerate(["id", "ls -l /tmp", "su - oracle", "cat /etc/security/passwd", "rm /var/adm/sulog"], 1):
    # Every command starts on an even byte; a number marker precedes the third.
    if len(body) % 2:
        body += b"\0"
    if n == 3:
        body += marker(3)
    body += command(text)
body += b"\x81\0"  # cancels `rm /var/adm/sulog`
body += command("exit")
with open(os.path.join(HERE, "sh_history"), "wb") as f:
    f.write(bytes(body))
