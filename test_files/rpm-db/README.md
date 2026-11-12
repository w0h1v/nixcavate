# rpm-db fixture

`rpmdb.sqlite` is a reduced copy of the RPM database of a throwaway `rockylinux:9` container
(aarch64, `dnf install -y nmap sqlite`, then `PRAGMA wal_checkpoint(TRUNCATE)`). The full
`/var/lib/rpm/rpmdb.sqlite` is 6 MB, so a new file was built with the same `Packages` table
definition holding five real header blobs copied unchanged (hnum 9, 143, 64, 38 and 85;
the four smallest headers plus `openssl-libs`, which has an epoch):

```python
import sqlite3
src = sqlite3.connect("rpmdb.sqlite.full")
d = sqlite3.connect("rpmdb.sqlite")
d.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)")
for i in (9, 143, 64, 38, 85):
    d.execute("INSERT INTO Packages VALUES (?, ?)",
              (i, src.execute("SELECT blob FROM Packages WHERE hnum=?", (i,)).fetchone()[0]))
d.commit(); d.execute("VACUUM")
```

Blobs in the table start directly with `index_count`; there is no 8-byte magic preamble.

## Berkeley DB `Packages`

`Packages` (little-endian, 212 KiB) and `Packages-s390x` (big-endian, 92 KiB) are fresh RPM
databases built in throwaway containers, each holding a few small real packages (`--justdb`,
so no files were installed) plus the distribution's signing key(s):

```sh
# Packages: amazonlinux:2 (aarch64), rpm 4.11, Berkeley DB hash version 9.
yum install -y yum-utils
mkdir -p /tmp/dl /tmp/r && cd /tmp/dl
yumdownloader basesystem setup libgcc tzdata-java
rpm --root /tmp/r --initdb
rpm --root /tmp/r --import /etc/pki/rpm-gpg/RPM-GPG-KEY-amazon-linux-2
rpm --root /tmp/r -i --nodeps --justdb --noscripts --notriggers *.rpm
cp /tmp/r/var/lib/rpm/Packages .

# Packages-s390x: docker run --platform linux/s390x registry.access.redhat.com/ubi8/ubi
# (rpm 4.14 under emulation; `file` reports "Berkeley DB (Hash, version 9, big-endian)").
mkdir -p /tmp/dl /tmp/r
dnf install -y --downloadonly --downloaddir /tmp/dl basesystem setup libgcc   # or `reinstall`
rpm --root /tmp/r --initdb
rpm --root /tmp/r --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
cd /tmp/dl && rpm --root /tmp/r -i --nodeps --justdb --noscripts --notriggers \
    basesystem-*.rpm setup-*.rpm libgcc-*.rpm
cp /tmp/r/var/lib/rpm/Packages Packages-s390x
```

`rpm --root /tmp/r -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH} %{INSTALLTIME}\n'` in the same
container lists exactly the five packages in each snapshot (`gpg-pubkey` prints arch `(none)`,
which the parser reports as empty).
