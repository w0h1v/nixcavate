# bsd-utmp fixtures

- `netbsd-wtmp`: the first 12 records (40 bytes each: `line[8] name[8] host[16]`, 64-bit time) of `/var/log/wtmp` of a throwaway NetBSD 10.1 guest (qemu, official live image) after a scripted run: users `alice`, `mallory`, `bob` (`useradd`), ssh logins and failed logins, `doas`/`su`, account changes, `pkg_add pkgin sudo tree jq zip doas` and `pkg_delete zip`, cron and at jobs, one reboot. Only example data.
- `openbsd-wtmp`: the first 10 records (304 bytes each: `line[8] name[32] host[256]`, 64-bit time) of `/var/log/wtmp` of a throwaway OpenBSD 7.8 guest (qemu, installed from the official `miniroot78.img`) after a scripted run of the same kind (`useradd`, `pkg_add sudo tree jq zip`, `pkg_delete zip`, `doas`, `su`, `crontab`, `at`, one reboot). Only example data.
- `*.truth`: the same records read with `fread()` of the libc's `struct utmp` (a C program in the guest: `line<TAB>name<TAB>host<TAB>time`).
