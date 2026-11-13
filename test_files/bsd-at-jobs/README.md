`/var/at/jobs/c0000101c86ae3`: the job `echo ... | at now + 2 days` queued by `alice` in the FreeBSD 14.5 guest (`echo alice > /var/at/at.allow` first).

`openbsd-1794710400.c`: `/var/cron/atjobs/1794710400.c`, the job queued by `alice` in a throwaway OpenBSD 7.8 guest (qemu, installed from the official `miniroot78.img`) after a scripted run of the same kind (`useradd`, `pkg_add sudo tree jq zip`, `pkg_delete zip`, `doas`, `su`, `crontab`, `at`, one reboot). Only example data. OpenBSD names a job by its run time in epoch seconds and its queue.
