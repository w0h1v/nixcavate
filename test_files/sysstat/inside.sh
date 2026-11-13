#!/bin/sh
# Runs inside a privileged container: sadc collects a few samples while some load runs, then
# sadf (the same sysstat) prints the file as JSON, which is the reference for the tests.
. /etc/os-release
if command -v apt-get >/dev/null; then
    apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq sysstat >/dev/null 2>&1
else
    (yum install -y -q sysstat || dnf install -y -q sysstat) >/dev/null 2>&1
fi
mkdir -p /out
SADC=$(command -v sadc || ls /usr/lib/sysstat/sadc /usr/lib64/sa/sadc 2>/dev/null | head -1)
SADF=$(command -v sadf)
(
  for i in 1 2 3 4 5 6 7; do
      dd if=/dev/zero of=/tmp/load.bin bs=1M count=64 conv=fsync 2>/dev/null
      for j in 1 2 3 4 5; do sh -c 'true' ; done
      cat /tmp/load.bin > /dev/null
      sleep 0.3
  done
) &
$SADC -S ALL 1 8 /out/sa13
wait
$SADF -j /out/sa13 -- -A > /out/sadf.json 2>/out/sadf.err
$SADF -d /out/sa13 -- -u -w -q > /out/sadf-d.csv 2>/dev/null
$SADF -H /out/sa13 > /out/sadf-header.txt 2>&1
$SADF --help 2>&1 | head -1 > /out/version
echo "$PRETTY_NAME $(uname -m)" > /out/os
for d in /sys/dev/block/*; do echo "$(basename $d) $(basename $(readlink $d))"; done > /out/devices.txt
ls -l /out/sa13 > /out/ls.txt
