#!/usr/bin/env python3
"""drive.py LINE... -- COMMAND ARGS: runs an interactive program on a pty, types the lines."""
import os, pty, sys, time, select
sep = sys.argv.index("--")
lines, cmd = sys.argv[1:sep], sys.argv[sep + 1:]
pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm"
    os.execvp(cmd[0], cmd)
def drain(t):
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                if not os.read(fd, 4096):
                    return
            except OSError:
                return
drain(1.5)
for line in lines:
    os.write(fd, (line + "\r").encode())
    drain(0.6)
os.write(fd, b"\x04")
drain(1.0)
for _ in range(40):           # give the program four seconds to leave and save its history
    try:
        done, _status = os.waitpid(pid, os.WNOHANG)
    except OSError:
        break
    if done:
        break
    drain(0.1)
else:
    os.kill(pid, 15)
