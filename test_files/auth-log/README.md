`freebsd-auth.log`: lines of `/var/log/auth.log` of a FreeBSD 14.5 guest (sshd-session, sudo, doas, su, shutdown).

`openbsd-messages` (the `useradd`, `usermod`, `userdel`, `groupadd` and `groupdel` lines of `/var/log/messages`) and `openbsd-secure` (`doas` lines of `/var/log/secure`) come from an OpenBSD 7.8 guest of the same kind (`pkg_add`, `useradd`/`usermod`/`userdel`/`groupadd`/`groupdel` and `doas` run by the scripted activity).
