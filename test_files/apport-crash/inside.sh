#!/bin/sh
# Runs inside a privileged Ubuntu container: apport's own library writes a crash report for a
# live process (as apport does for a crash, minus the kernel pipe), and apport-unpack
# splits it into its fields as the reference.
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq apport python3-apport >/dev/null 2>&1
useradd -m alice
mkdir -p /out /var/crash
cp /bin/sleep /tmp/my-daemon
setpriv --reuid=$(id -u alice) --regid=$(id -g alice) --clear-groups /tmp/my-daemon 1000 &
pid=$!
sleep 1
python3 - $pid <<'PY'
import sys, apport.report
pid = int(sys.argv[1])
r = apport.report.Report('Crash')
r.add_proc_info(pid)
r.add_os_info()
r['Signal'] = '11'
r['SignalName'] = 'SIGSEGV'
r['ExecutablePath'] = '/tmp/my-daemon'
r['Package'] = 'coreutils 9.4-3ubuntu6'
open('/tmp/core.bin', 'wb').write(bytes(range(256)) * 400)
r['CoreDump'] = (open('/tmp/core.bin', 'rb'), True, None, True)  # binary: written as base64 after the text
with open('/var/crash/_tmp_my-daemon.1001.crash', 'wb') as f:
    r.write(f)
PY
kill -9 $pid
cp /var/crash/*.crash /out/
apport-unpack /var/crash/_tmp_my-daemon.1001.crash /out/unpacked
cp /etc/passwd /out/passwd
(cd /out/unpacked && for f in ProblemType Date ExecutablePath ProcCmdline Signal Package Architecture; do printf '%s=%s\n' "$f" "$(cat $f)"; done; grep '^Uid' ProcStatus) > /out/reference.txt
rm -rf /out/unpacked
ls -la /out > /out/ls.txt
