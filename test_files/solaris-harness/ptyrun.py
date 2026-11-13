#!/usr/bin/python3
"""ptyrun.py [-p PW]... [-e ENDMARK] -- cmd args... : runs cmd on a pty, answering each password-like prompt
with the next -p value (a value of '' sends a bare newline). Prints the transcript. Example data only."""
import os, pty, select, sys, time
args = sys.argv[1:]
pws = []; login = None
while args and args[0] in ('-p', '-l'):
    if args[0] == '-p': pws.append(args[1])
    else: login = args[1]
    args = args[2:]
if args and args[0] == '--': args = args[1:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(args[0], args)
buf = b''; out = b''; i = 0; deadline = time.time() + 60
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 5)
    if not r:
        break
    try:
        d = os.read(fd, 4096)
    except OSError:
        break
    if not d:
        break
    out += d; buf += d
    low = buf.lower()
    if login and low.rstrip().endswith(b'login:'):
        os.write(fd, login.encode() + b'\n'); buf = b''; continue
    if low.rstrip().endswith((b'assword:', b'assword: ')) or low.rstrip().endswith(b'password:'):
        if i < len(pws):
            os.write(fd, pws[i].encode() + b'\n'); i += 1
        else:
            os.write(fd, b'\n')
        buf = b''
st = 0
for _ in range(50):
    try:
        done, st = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        break
    if done:
        break
    time.sleep(0.1)
else:
    os.kill(pid, 9); st = 255 << 8
sys.stdout.write(out.decode('utf-8', 'replace').replace('\r', ''))
sys.exit((st >> 8) & 255)
