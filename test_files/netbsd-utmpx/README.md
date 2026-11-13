# utmpx fixture

`netbsd-wtmpx`: the first 14 records (520 bytes each) of `/var/log/wtmpx` of a throwaway NetBSD 10.1 guest (qemu, official live image) after a scripted run: users `alice`, `mallory`, `bob` (`useradd`), ssh logins and failed logins, `doas`/`su`, account changes, `pkg_add pkgin sudo tree jq zip doas` and `pkg_delete zip`, cron and at jobs, one reboot. Only example data. `netbsd-wtmpx.truth`: the same records read with `fread()` of the libc's `struct utmpx`
(`type seconds microseconds name id line host pid session`); `getutxent()` cannot read a `wtmpx` log, so the C program used `fread()` on a copy.
