# wtmpx fixture

`wtmpx` is `/var/adm/wtmpx` of illumos (OmniOS r151054, x86) in a throwaway KVM guest; example users only: two boots, run-level changes, a reboot, `inittab` and
getty records, and seven ssh logins with their logouts (38 records of 372 bytes). `fwtmp.txt` is
`/usr/lib/acct/fwtmp < wtmpx` run on the same bytes, the reference the test compares every field with.
The harness that produced it: `nxsol.sh` (users alice and mallory, five key logins, failed password logins, a reboot).
