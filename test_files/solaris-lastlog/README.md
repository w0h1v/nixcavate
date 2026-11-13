# solaris-lastlog fixture

`lastlog.v2` is `/var/adm/lastlog.v2` (304-byte records indexed by uid) of illumos (OmniOS r151054, x86) in a throwaway KVM guest; example users only, copied just before the
interactive ssh login whose banner is in `banner.txt` (`Last login: ... from ...` is printed by sshd from this file).
`passwd` is the guest's `/etc/passwd` at that moment. The old 28-byte `lastlog` form is built in the tests from `lastlog.h`.
