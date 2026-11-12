# dnf-history fixture

`history.sqlite` comes from a throwaway `rockylinux:9` container (aarch64) after
`dnf install -y nmap sqlite`, `dnf reinstall -y nmap-ncat` and `dnf remove -y nmap`, then
`PRAGMA wal_checkpoint(TRUNCATE)` so the file is self-contained.
