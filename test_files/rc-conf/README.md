`rc.conf` of the FreeBSD 14.5 guest, unchanged. Produced in a throwaway FreeBSD 14.5 guest (qemu, official `BASIC-CLOUDINIT` UFS image, UTC, auditd enabled) after a scripted
run: users `alice`, `mallory` and `bob` created with `pw useradd`, five key logins by `alice` over ssh, failed
password logins for `mallory` and a missing user, `sudo`/`doas`/`su` use, account changes, `pkg install`/`pkg delete`,
cron and at jobs, one reboot. Only example data.

`openbsd-rc.conf.local`: `/etc/rc.conf.local` of a throwaway OpenBSD 7.8 guest (qemu, installed from the official `miniroot78.img`) after a scripted run of the same kind (`useradd`, `pkg_add sudo tree jq zip`, `pkg_delete zip`, `doas`, `su`, `crontab`, `at`, one reboot). Only example data.
