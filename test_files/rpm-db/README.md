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
