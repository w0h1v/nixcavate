#!/bin/sh
# Runs inside a privileged container (see generate.sh): turns process accounting on with
# accton, runs a scripted set of commands as root, alice and bob, and writes the accounting
# file plus what the real tools (dump-acct, lastcomm) print for it to /out.
. /etc/os-release
if command -v apt-get >/dev/null; then
    apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq acct >/dev/null 2>&1
else
    (yum install -y -q psacct || dnf install -y -q psacct) >/dev/null 2>&1
fi
mkdir -p /out
for u in alice bob; do useradd -m $u 2>/dev/null || adduser --disabled-password --gecos '' $u; done
touch /var/log/pacct.t
accton /var/log/pacct.t
/bin/true
su -s /bin/sh alice -c '/bin/ls / >/dev/null'
su -s /bin/sh bob -c '/bin/echo hi >/dev/null'
sh -c '(true); (true)'                                   # forks without exec: AFORK
su -s /bin/sh alice -c 'sh -c "(exit 3)"; /bin/sleep 1'  # exit status 3; a run of one second
sh -c 'ulimit -c unlimited; kill -SEGV $$' 2>/dev/null   # core dump + killed by a signal
sh -c 'kill -KILL $$' 2>/dev/null                        # killed by a signal
sh -c 'exit 42'
sh -c 'cp /bin/true /tmp/t; chmod 4755 /tmp/t; chown bob /tmp/t'
setpriv --reuid=bob --regid=bob --clear-groups /tmp/t    # a setuid program run by bob
setpriv --reuid=alice --regid=alice --clear-groups sh -c 'sleep 2 & wait'
sleep 1
accton
cp /var/log/pacct.t /out/pacct
cp /etc/passwd /out/passwd
echo "$PRETTY_NAME $(uname -m)" > /out/os
dump-acct /out/pacct > /out/dump-acct.txt 2>&1
lastcomm -f /out/pacct > /out/lastcomm.txt 2>&1
# The same records in the layouts dump-acct can write. The kernel here only writes version 3,
# so these are converted by the real tool, not made by an old kernel.
for f in 2 0; do dump-acct --raw --format $f /out/pacct > /out/pacct.v$f 2>/dev/null; dump-acct /out/pacct.v$f > /out/dump-acct.v$f.txt 2>&1; done
dump-acct --raw --byteswap /out/pacct > /out/pacct.swapped 2>/dev/null; dump-acct /out/pacct.swapped > /out/dump-acct.swapped.txt 2>&1
dump-acct --raw --byteswap --format 2 /out/pacct > /out/pacct.v2swapped 2>/dev/null; dump-acct /out/pacct.v2swapped > /out/dump-acct.v2swapped.txt 2>&1
