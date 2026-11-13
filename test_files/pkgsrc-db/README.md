# pkgsrc-db fixtures

`usr/pkg/pkgdb/` of a throwaway NetBSD 10.1 guest (qemu, official live image) after a scripted run: users `alice`, `mallory`, `bob` (`useradd`), ssh logins and failed logins, `doas`/`su`, account changes, `pkg_add pkgin sudo tree jq zip doas` and `pkg_delete zip`, cron and at jobs, one reboot. Only example data. Two packages (`tree-1.8.0`, and `oniguruma-6.9.10` which was pulled in by `jq`: its `+INSTALLED_INFO` says `automatic=yes`), the files the parser reads
(`+CONTENTS`, `+BUILD_INFO` cut to its identifying keys, `+COMMENT`, `+SIZE_PKG`, `+INSTALLED_INFO`), and the real `pkgdb.byfile.db` (a Berkeley DB 1.85 hash file the parser does not read; it is the anchor).
`mtimes.txt`: the modification times of the two `+CONTENTS` files in the guest (the install times; the test host keeps no modification times).
