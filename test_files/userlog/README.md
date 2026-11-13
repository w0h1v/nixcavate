`/var/log/userlog` of the FreeBSD 14.5 guest after the scripted run (pw/adduser/rmuser account changes). Produced in a throwaway FreeBSD 14.5 guest (qemu, official `BASIC-CLOUDINIT` UFS image, UTC, auditd enabled) after a scripted
run: users `alice`, `mallory` and `bob` created with `pw useradd`, five key logins by `alice` over ssh, failed
password logins for `mallory` and a missing user, `sudo`/`doas`/`su` use, account changes, `pkg install`/`pkg delete`,
cron and at jobs, one reboot. Only example data.
