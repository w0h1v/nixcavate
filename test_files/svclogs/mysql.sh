#!/bin/sh
# MariaDB 10.11 (Debian 12): error log, general log, slow log; and MySQL 8.4 (official image): error log, general log, slow log.
# Output: $1/mariadb/*, $1/mysql/*
set -eu
out="$1"; mkdir -p "$out/mariadb" "$out/mysql"
docker run --rm --platform linux/arm64 debian:12 sh -c '
exec 3>&1 1>&2
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq mariadb-server >/dev/null 2>&1
mkdir -p /var/log/mysql; chown mysql /var/log/mysql
cat > /etc/mysql/mariadb.conf.d/99-nx.cnf <<EOC
[mysqld]
log_error=/var/log/mysql/error.log
general_log=1
general_log_file=/var/log/mysql/general.log
slow_query_log=1
slow_query_log_file=/var/log/mysql/slow.log
long_query_time=0
log_slow_verbosity=query_plan
EOC
(mysqld_safe --user=mysql --log-error=/var/log/mysql/error.log >/dev/null 2>&1 &); sleep 8
mariadb -e "CREATE USER alice@localhost IDENTIFIED BY '"'"'Example-Pass-1'"'"'; GRANT ALL ON *.* TO alice@localhost; CREATE DATABASE appdb;"
mariadb -ualice -pExample-Pass-1 appdb -e "CREATE TABLE t(id int, v text); INSERT INTO t VALUES (1,'"'"'a'"'"'),(2,'"'"'b'"'"'); SELECT * FROM t WHERE id=1; SELECT sleep(0.2);"
mariadb -ualice -pwrong -e "select 1" 2>/dev/null || true
mariadb -unosuch -pwrong -e "select 1" 2>/dev/null || true
mariadb -ualice -pExample-Pass-1 -e "SELECT 1,
  2
FROM dual; DROP DATABASE appdb;"
mariadb -e "SHUTDOWN" 2>/dev/null; sleep 4
mkdir /o; cp /var/log/mysql/* /o/; cd /o; tar cf - . >&3' | tar -C "$out/mariadb" -xf -
docker rm -f nxmysql >/dev/null 2>&1 || true
docker run -d --name nxmysql --platform linux/arm64 -e MYSQL_ROOT_PASSWORD=Example-Root-1 mysql:8.4 --general-log=1 --general-log-file=/var/lib/mysql/general.log --slow-query-log=1 --slow-query-log-file=/var/lib/mysql/slow.log --long-query-time=0 --log-error=/var/lib/mysql/error.log --log-error-verbosity=3 >/dev/null
for i in $(seq 60); do docker exec nxmysql mysqladmin -uroot -pExample-Root-1 ping >/dev/null 2>&1 && break; sleep 2; done
sleep 3
docker exec nxmysql mysql -uroot -pExample-Root-1 -e "CREATE USER alice@'%' IDENTIFIED BY 'Example-Pass-1'; GRANT ALL ON *.* TO alice@'%'; CREATE DATABASE appdb; USE appdb; CREATE TABLE t(id int); INSERT INTO t VALUES (1); SELECT * FROM t; SELECT sleep(0.2)" 2>/dev/null
docker exec nxmysql mysql -ualice -pwrong -h127.0.0.1 -e "select 1" >/dev/null 2>&1 || true
docker exec nxmysql mysql -ualice -pExample-Pass-1 -h127.0.0.1 -e "SELECT 1,
  2" >/dev/null 2>&1
sleep 2
docker exec nxmysql sh -c 'cd /var/lib/mysql && tar cf - error.log general.log slow.log' | tar -C "$out/mysql" -xf -
docker rm -f nxmysql >/dev/null
# The image initialises the server first and logs 13 MiB of its own SQL: keep the file headers and what follows our first statement.
python3 - "$out/mysql" <<'EOP'
import sys
d = sys.argv[1]
def trim(name, marker, back):
    lines = open(f"{d}/{name}", errors="replace").read().split("\n")
    head = lines[:3]
    at = next(i for i, l in enumerate(lines) if marker in l)
    while not back(lines[at]):
        at -= 1
    open(f"{d}/{name}", "w").write("\n".join(head + lines[at:]))
trim("general.log", "CREATE USER 'alice'", lambda l: "Connect" in l)
trim("slow.log", "CREATE USER 'alice'", lambda l: l.startswith("# Time:"))
EOP
