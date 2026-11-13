# Solaris/illumos fixture harness

The scripts that produced the real Solaris-family fixtures in this directory (`wtmpx`, `utmpx`, `solaris-lastlog`,
`sulog`, `loginlog`, `cron-log`, `smf-*`, `ips-*`, `svr4-*`, `user-attr`, `rbac-profiles`, `crle-config` and the rest):
two throwaway OmniOS guests (r151054 LTS and r151060, x86, KVM, user-mode networking, example users alice, mallory and bob).

* `nxsol.sh phase1` creates the users and roles, logs in over ssh (key and wrong password), runs `su`, `sudo`, `pfexec`,
  installs and removes packages, builds one SVR4 package with `pkgmk` and `pkgadd`, schedules cron and `at` jobs, plants the
  persistence examples (every marker is `NXMK_*`), waits for cron, and reboots. `nxsol.sh phase2` logs in again and captures
  the guest's own tool output (`last`, `fwtmp`, `svcs`, `pkg history -l`, `praudit`...) and the UAC and tar collections.
* `nxsol3.sh` copies `lastlog.v2` before an interactive login (the banner is the reference) and dumps the SMF repository with its own `sqlite` shell.
* `auth-log/solaris_authlog` and `syslog/solaris_messages` are lines of `/var/log/authlog` and `/var/adm/messages` of the same guests (rsyslog's `[ID n facility.level]` prefixes; the host name is replaced by `host1`).
* `ptyrun.py` answers password prompts on a pty (`passwd`, `su`, `login`, `ssh`).

The scripts are kept as they were run; nothing here runs in the test suite.
