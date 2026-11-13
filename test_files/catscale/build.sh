#!/bin/sh
# Builds the CatScale command-output fixtures with the real commands, run the way
# Cat-Scale.sh runs them (same options, same file-name suffixes), in a throwaway container:
#   sh test_files/catscale/build.sh
# Needs Docker. Output goes to test_files/catscale/.
set -eu
out="$(cd "$(dirname "$0")" && pwd)"
name=nxc-catscale-fixture-$$
docker run -d --rm --platform linux/arm64 --name "$name" debian:12 sleep 600 >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker exec "$name" sh -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq procps net-tools iproute2 lsof kmod netcat-openbsd >/dev/null'
docker exec -d "$name" sh -c 'nc -l -p 4444 >/dev/null 2>&1; true'
docker exec -d "$name" sh -c 'nc -u -l -p 5353 >/dev/null 2>&1; true'
docker exec -d "$name" sh -c 'sleep 301'
sleep 2
p=host-20261112-1838
docker exec "$name" sh -c '
  ps axwwSo user,pid,ppid,vsz,rss,tname,stat,stime,time,args > /tmp/processes-axwwSo.txt
  ss -anepo > /tmp/ss-anepo.txt
  netstat -pvWanoee > /tmp/netstat-pvWanoee.txt
  netstat -antup > /tmp/netstat-antup.txt
  netstat -an > /tmp/netstat-an.txt
  lsof +c0 -M -R -V -w -n -P > /tmp/lsof-list-open-files.txt 2>/dev/null
  lsmod > /tmp/lsmod.txt 2>/dev/null || true
'
for f in processes-axwwSo ss-anepo netstat-pvWanoee netstat-antup netstat-an lsof-list-open-files lsmod; do
  docker cp "$name:/tmp/$f.txt" "$out/$p-$f.txt"
done
