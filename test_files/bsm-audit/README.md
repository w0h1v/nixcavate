# bsm-audit fixtures

- `freebsd.audit`: 20 records of a real FreeBSD audit trail (`/var/audit/<start>.<end>`, flags `lo,aa,ex,pc`, policy
  `cnt,argv,arge`), cut at record boundaries: records 1-3 (su, OpenSSH login, fork) and 41-58 (setegid, chdir, execve with
  arguments and environment, ...) of the first trail of the run. Produced in a throwaway FreeBSD 14.5 guest (qemu, official `BASIC-CLOUDINIT` UFS image, UTC, auditd enabled) after a scripted
run: users `alice`, `mallory` and `bob` created with `pw useradd`, five key logins by `alice` over ssh, failed
password logins for `mallory` and a missing user, `sudo`/`doas`/`su` use, account changes, `pkg install`/`pkg delete`,
cron and at jobs, one reboot. Only example data.
- `freebsd.audit.praudit-l`: `praudit -l` of the same trail, for those 20 records.
- `macos-synthetic.audit`, `tokens-synthetic.audit`: **synthetic**, written by `make_synthetic.py` from audit.log(5) and
  OpenBSM's `audit_record.h`. A macOS trail needs root to produce, and a FreeBSD amd64 kernel writes none of the 64-bit or
  socket tokens, so macOS event numbering and those token layouts are covered only by these files.
