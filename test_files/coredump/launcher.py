#!/usr/bin/env python3
"""Stands in for systemd-coredump.socket: a SEQPACKET socket at /run/systemd/coredump that
runs the real /lib/systemd/systemd-coredump for each connection, as Accept=yes does."""
import os, socket, sys
path = "/run/systemd/coredump"
os.makedirs(os.path.dirname(path), exist_ok=True)
if os.path.exists(path):
    os.unlink(path)
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.bind(path)
os.chmod(path, 0o666)
s.listen(16)
while True:
    conn, _ = s.accept()
    if os.fork() == 0:
        os.dup2(conn.fileno(), 3)
        env = dict(os.environ, LISTEN_FDS="1", LISTEN_PID=str(os.getpid()))
        os.execve("/lib/systemd/systemd-coredump", ["/lib/systemd/systemd-coredump"], env)
    conn.close()
