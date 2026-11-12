#!/usr/bin/env python3
"""Generates the synthetic Linux benchmark host: a UAC-style collection of large text logs.

    gen_corpus.py OUT_DIR [--mib 512] [--seed 1]

The output is deterministic for a given size and seed, so its throughput can be compared
between builds and its record counts between releases. All names and addresses are from
documentation ranges. journald files are not generated here (they need systemd tooling);
see bench/README.md.
"""
import argparse
import os
import random
import time

USERS = ["alice", "bob", "carol", "deploy", "root"]
IPS = [f"203.0.113.{n}" for n in range(1, 60)] + [f"198.51.100.{n}" for n in range(1, 40)] + ["2001:db8::7"]
PROGRAMS = ["systemd", "cron", "kernel", "dockerd", "NetworkManager", "rsyslogd", "sshd", "postfix/smtpd"]
PATHS = ["/", "/index.html", "/api/v1/items?id=42", "/login", "/static/app.js", "/wp-login.php", "/health"]
AGENTS = ["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36", "curl/8.5.0", "python-requests/2.31"]
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
START = 1_709_251_200  # 2024-03-01T00:00:00Z


def syslog(rng, t):
    tm = time.gmtime(t)
    program = rng.choice(PROGRAMS)
    return f"{MONTHS[tm.tm_mon - 1]} {tm.tm_mday:2d} {tm.tm_hour:02d}:{tm.tm_min:02d}:{tm.tm_sec:02d} bench01 {program}[{rng.randint(1, 65000)}]: Started session {rng.randint(1, 99999)} of user {rng.choice(USERS)} on unit run-{rng.randint(1000, 9999)}.scope\n"


def auth(rng, t):
    tm = time.gmtime(t)
    stamp = f"{MONTHS[tm.tm_mon - 1]} {tm.tm_mday:2d} {tm.tm_hour:02d}:{tm.tm_min:02d}:{tm.tm_sec:02d} bench01"
    user, ip, pid, port = rng.choice(USERS), rng.choice(IPS), rng.randint(1, 65000), rng.randint(1024, 65000)
    kind = rng.randint(0, 4)
    if kind == 0:
        return f"{stamp} sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 SHA256:n0tArealF1ngerpr1ntJustF0rBenchmarks0000000000\n"
    if kind == 1:
        return f"{stamp} sshd[{pid}]: Failed password for invalid user admin from {ip} port {port} ssh2\n"
    if kind == 2:
        return f"{stamp} sudo:    {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx\n"
    if kind == 3:
        return f"{stamp} sshd[{pid}]: pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)\n"
    return f"{stamp} sshd[{pid}]: Connection closed by authenticating user {user} {ip} port {port} [preauth]\n"


def audit(rng, t):
    serial, pid = rng.randint(1, 9_999_999), rng.randint(1, 65000)
    stamp = f"msg=audit({t}.{rng.randint(0, 999):03d}:{serial})"
    kind = rng.randint(0, 3)
    if kind == 0:
        return f'type=SYSCALL {stamp}: arch=c000003e syscall=59 success=yes exit=0 a0=55d0 a1=55d1 a2=55d2 a3=8 items=2 ppid={pid - 1} pid={pid} auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="exec"\n'
    if kind == 1:
        return f'type=EXECVE {stamp}: argc=3 a0="curl" a1="-s" a2="https://example.com/"\n'
    if kind == 2:
        return f'type=PATH {stamp}: item=0 name="/usr/bin/curl" inode=1234 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL\n'
    return f"type=USER_AUTH {stamp}: pid={pid} uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=pam_unix acct=\"{rng.choice(USERS)}\" exe=\"/usr/sbin/sshd\" hostname={rng.choice(IPS)} addr={rng.choice(IPS)} terminal=ssh res=success'\n"


def access(rng, t):
    tm = time.gmtime(t)
    stamp = f"{tm.tm_mday:02d}/{MONTHS[tm.tm_mon - 1]}/{tm.tm_year}:{tm.tm_hour:02d}:{tm.tm_min:02d}:{tm.tm_sec:02d} +0000"
    return f'{rng.choice(IPS)} - - [{stamp}] "GET {rng.choice(PATHS)} HTTP/1.1" {rng.choice([200, 200, 200, 301, 404, 500])} {rng.randint(100, 90000)} "https://example.com/" "{rng.choice(AGENTS)}"\n'


def docker_json(rng, t):
    tm = time.gmtime(t)
    stamp = f"{tm.tm_year}-{tm.tm_mon:02d}-{tm.tm_mday:02d}T{tm.tm_hour:02d}:{tm.tm_min:02d}:{tm.tm_sec:02d}.{rng.randint(0, 999999999):09d}Z"
    return f'{{"log":"level=info msg=\\"handled request\\" path={rng.choice(PATHS)} status=200 duration={rng.randint(1, 900)}ms\\n","stream":"stdout","time":"{stamp}"}}\n'


def dpkg(rng, t):
    tm = time.gmtime(t)
    stamp = f"{tm.tm_year}-{tm.tm_mon:02d}-{tm.tm_mday:02d} {tm.tm_hour:02d}:{tm.tm_min:02d}:{tm.tm_sec:02d}"
    return f"{stamp} status installed lib{rng.randint(1, 9999)}:amd64 1.{rng.randint(0, 99)}-{rng.randint(1, 9)}\n"


def bodyfile(rng, t):
    name = f"/usr/lib/x86_64-linux-gnu/lib{rng.randint(1, 999999)}.so.{rng.randint(0, 9)}"
    return f"0|{name}|{rng.randint(2, 9_999_999)}|-rw-r--r--|0|0|{rng.randint(1, 5_000_000)}|{t}|{t - 86400}|{t - 3600}|{t - 172800}\n"


FILES = [  # (path, line generator, share of the total size)
    ("[root]/var/log/syslog", syslog, 0.22),
    ("[root]/var/log/auth.log", auth, 0.18),
    ("[root]/var/log/audit/audit.log", audit, 0.18),
    ("[root]/var/log/nginx/access.log", access, 0.16),
    ("[root]/var/lib/docker/containers/3f2a1b/3f2a1b-json.log", docker_json, 0.12),
    ("[root]/var/log/dpkg.log", dpkg, 0.04),
    ("bodyfile/bodyfile.txt", bodyfile, 0.10),
]
SMALL = {
    "[root]/etc/hostname": "bench01\n",
    "[root]/etc/os-release": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n',
    "[root]/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n",
    "[root]/etc/timezone": "Etc/UTC\n",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("out")
    parser.add_argument("--mib", type=int, default=512)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    for path, text in SMALL.items():
        full = os.path.join(args.out, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(text)
    for index, (path, line, share) in enumerate(FILES):
        rng = random.Random(args.seed * 1000 + index)
        target = int(args.mib * (1 << 20) * share)
        full = os.path.join(args.out, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        written, t = 0, START
        with open(full, "w") as f:
            while written < target:
                block = []
                for _ in range(2000):
                    t += rng.randint(0, 2)
                    block.append(line(rng, t))
                text = "".join(block)
                f.write(text)
                written += len(text)
        # A fixed modification time keeps year inference, and so the output, repeatable.
        os.utime(full, (t + 60, t + 60))
        print(f"{written / (1 << 20):8.1f} MiB  {path}")


if __name__ == "__main__":
    main()
