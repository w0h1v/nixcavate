# utmpx fixture

`utmpx` is `/var/adm/utmpx` of the same guest as `wtmpx` (7 records: boot, run level, getty and `inittab`
entries). `fwtmp.txt` is `/usr/lib/acct/fwtmp < utmpx` on the same bytes.
