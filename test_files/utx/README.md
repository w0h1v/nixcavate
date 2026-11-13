# utx fixtures

Produced in a throwaway FreeBSD 14.5 guest (qemu, official `BASIC-CLOUDINIT` UFS image, UTC, auditd enabled) after a scripted
run: users `alice`, `mallory` and `bob` created with `pw useradd`, five key logins by `alice` over ssh, failed
password logins for `mallory` and a missing user, `sudo`/`doas`/`su` use, account changes, `pkg install`/`pkg delete`,
cron and at jobs, one reboot. Only example data.

- `utx.log`: the first 6 records (two boot records, a login and its end, another login and its end) of `/var/log/utx.log`
  (the file keeps a 16-bit length before each record).
- `utx.lastlogin`, `utx.active`: `/var/log/utx.lastlogin` and `/var/run/utx.active` unchanged (fixed 197-byte records).
- `*.truth`: the same records read with libc's `getutxent()` after `setutxdb()` (a 20-line C program in the guest:
  `type<TAB>seconds<TAB>microseconds<TAB>id<TAB>pid<TAB>user<TAB>line<TAB>host`).
