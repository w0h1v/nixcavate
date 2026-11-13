#!/bin/sh
# PostgreSQL 15 (Debian 12): the Debian log_line_prefix, the upstream one, csvlog and jsonlog.
# Output: $1/postgres/{pg-01.log,pg-01.csv,pg-01.json} (Debian prefix) and plain-01.* (upstream prefix)
set -eu
out="$1"; mkdir -p "$out/postgres"
here="$(cd "$(dirname "$0")" && pwd)"
docker run --rm --platform linux/arm64 -v "$here/postgres-extra.conf:/extra.conf:ro" -v "$here/postgres-plain.conf:/plain.conf:ro" debian:12 sh -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq postgresql >/dev/null 2>&1
cd /; D=/etc/postgresql/15/main
cat /extra.conf >> $D/postgresql.conf
echo "host all all 127.0.0.1/32 scram-sha-256" >> $D/pg_hba.conf
service postgresql start >/dev/null 2>&1; sleep 4
su postgres -c "psql -qc \"CREATE ROLE alice LOGIN PASSWORD '"'"'Example-Pass-1'"'"'\"; psql -qc \"CREATE DATABASE appdb OWNER alice\""
drive() {
  export PGPASSWORD=Example-Pass-1
  psql -qh 127.0.0.1 -U alice appdb -c "CREATE TABLE t(id int primary key, name text)" -c "INSERT INTO t VALUES (1,\$\$a\$\$)" || true
  psql -qh 127.0.0.1 -U alice appdb -c "INSERT INTO t VALUES (1,\$\$dup\$\$)" 2>/dev/null || true
  psql -qh 127.0.0.1 -U alice appdb -c "SELECT * FROM nosuchtable" 2>/dev/null || true
  psql -qh 127.0.0.1 -U alice appdb -c "SELECT id,
     name
   FROM t
  WHERE id = 1" >/dev/null
  PGPASSWORD=wrong psql -qh 127.0.0.1 -U alice appdb -c "select 1" 2>/dev/null || true
  psql -qh 127.0.0.1 -U nosuchuser appdb -c "select 1" 2>/dev/null || true
  psql -qh 127.0.0.1 -U alice nosuchdb -c "select 1" 2>/dev/null || true
  psql -qh 127.0.0.1 -U alice appdb -c "DROP TABLE IF EXISTS t" >/dev/null
}
drive
service postgresql stop >/dev/null 2>&1; sleep 2
mkdir -p /out; cp /var/log/postgresql/pg-* /out/; ls /var/log/postgresql >&2
rm -f /var/log/postgresql/pg-*
# Second run: the upstream default prefix.
cat /plain.conf >> $D/postgresql.conf
service postgresql start >/dev/null 2>&1; sleep 4
drive
service postgresql stop >/dev/null 2>&1; sleep 2
cp /var/log/postgresql/plain-* /out/ 
cd /out; tar cf - .' > "$out/postgres/raw.tar"
cd "$out/postgres" && tar xf raw.tar && rm raw.tar && ls
