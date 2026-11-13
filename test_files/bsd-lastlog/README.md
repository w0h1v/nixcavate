# bsd-lastlog fixture

`netbsd-lastlog` is `/var/log/lastlog` of a throwaway NetBSD 10.1 guest (qemu, official live image) after a scripted run: users `alice`, `mallory`, `bob` (`useradd`), ssh logins and failed logins, `doas`/`su`, account changes, `pkg_add pkgin sudo tree jq zip doas` and `pkg_delete zip`, cron and at jobs, one reboot. Only example data. One 32-byte record (64-bit time, `line[8]`, `host[16]`) per uid, 1002 uids.
`netbsd-lastlog.truth`: `fread()` of the libc's `struct lastlog`, only the records with a time (`uid<TAB>time<TAB>line<TAB>host`).
OpenBSD's 272-byte records are checked only by a synthetic test (a real OpenBSD `lastlog` is 272 KiB for 1002 uids; it was compared with the libc dump in the corpus run instead).
