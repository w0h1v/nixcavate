#!/bin/sh
# Runs inside a privileged container: real systemd-coredump and journald (no systemd as PID 1),
# fed real core files made with gcore, the way the kernel's core_pattern pipe would. Writes the
# coredump directory and the tools' own listings to /out.
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq systemd systemd-coredump gdb python3 >/dev/null 2>&1
for u in alice bob; do adduser --disabled-password --gecos '' $u >/dev/null 2>&1; done
mkdir -p /run/systemd/journal /var/log/journal /var/lib/systemd/coredump /out
/lib/systemd/systemd-journald >/dev/null 2>&1 &
sleep 2
python3 /launcher.py &
sleep 1
ulimit -c unlimited
echo '/tmp/kcore.%p' > /proc/sys/kernel/core_pattern   # this container's own view of the sysctl
crash() { # name uid signal-name signal-number
    cp /bin/sleep "/tmp/$1"
    # A victim the kernel really dumps core for, and a twin with the same command line that is
    # kept alive (stopped) for systemd-coredump to inspect, as the kernel keeps the crashing one.
    setpriv --reuid=$2 --regid=$2 --clear-groups "/tmp/$1" 1000 &
    victim=$!
    setpriv --reuid=$2 --regid=$2 --clear-groups "/tmp/$1" 1000 &
    twin=$!
    sleep 1
    kill -$3 $victim
    sleep 1
    kill -STOP $twin
    # %P %u %g %s %t RLIMIT %h %d, as in the kernel.core_pattern sysctl systemd installs
    /lib/systemd/systemd-coredump $twin $2 $2 $4 $(date +%s) 9223372036854775808 buildhost 1 < /tmp/kcore.$victim
    kill -9 $twin
    sleep 1
}
crash web-server 1000 SEGV 11
crash my-app.v2 1001 ABRT 6
crash "odd name" 0 ILL 4
journalctl --flush; sleep 1
cp -a /var/lib/systemd/coredump/. /out/
coredumpctl list --no-pager > /out/coredumpctl-list.txt 2>&1
coredumpctl list --no-pager --json=short > /out/coredumpctl-list.json 2>&1
journalctl -o json --no-pager -t systemd-coredump > /out/journal-coredump.json 2>&1
ls -la /var/lib/systemd/coredump > /out/ls.txt
cat /etc/os-release | head -2 > /out/os
