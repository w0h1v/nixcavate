#!/bin/sh
# Runs inside a privileged container with a tty (see generate.sh): real sudo sessions with
# input/output logging and a log file, then what sudoreplay says about them. Writes to /out.
if command -v apt-get >/dev/null; then
    apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq sudo python3 >/dev/null 2>&1
else
    (yum install -y -q sudo python3 || dnf install -y -q sudo python3) >/dev/null 2>&1
fi
mkdir -p /out /var/log/sudo-io
for u in alice bob; do useradd -m $u 2>/dev/null || adduser --disabled-password --gecos '' $u; echo "$u:pw-$u" | chpasswd; done
sudo -V | head -1 > /out/version
cat > /etc/sudoers.d/nx <<SUDOERS
Defaults log_input, log_output, iolog_dir=/var/log/sudo-io, logfile=/var/log/sudo.log, !syslog
Defaults compress_io
alice ALL=(bob) NOPASSWD: /bin/ls, /bin/echo, /bin/sh
alice ALL=(bob) /bin/true
bob ALL=(ALL) NOPASSWD: /bin/true
SUDOERS
chmod 440 /etc/sudoers.d/nx
as() { u=$1; shift; su -s /bin/sh $u -c "$*" >> /out/session-output.txt 2>&1; }
# the same on a pty, so that sudo logs ttyin and ttyout and records the terminal
aspty() { u=$1; shift; python3 -c 'import pty, sys; pty.spawn(["setpriv", "--reuid=" + sys.argv[1], "--regid=" + sys.argv[1], "--clear-groups", "/bin/sh", "-c", "export HOME=/tmp; " + sys.argv[2]])' $(id -u $u) "$*" >> /out/session-output.txt 2>&1; }
LONG=$(printf 'argument-%s ' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20)
as alice "echo pw-alice | sudo -S -u bob /bin/true"
as alice "sudo -u bob /bin/sh -c 'echo out-one; echo err-one >&2; sleep 1; echo out-two'"
as alice "sudo -u bob /bin/ls /home"
as alice "sudo -u bob /bin/echo $LONG"
as alice "echo wrong | sudo -S -u bob /bin/true"
aspty alice "cd /tmp; sudo -u bob /bin/sh -c 'echo typed-on-a-tty; sleep 1; echo done'"
as alice "sudo -n -u root /usr/bin/id"
as bob "sudo -n /bin/true"
cat /var/log/sudo.log > /out/sudo.log
# a second pass with the JSON event log (sudo 1.9.4 and later), I/O logs uncompressed
if sudo -V | grep -q 'Sudo version 1\.9\.\(1[0-9]\|[4-9]\)'; then
    sed -i 's|logfile=/var/log/sudo.log|logfile=/var/log/sudo.json, log_format=json|; /compress_io/d' /etc/sudoers.d/nx
    as alice "sudo -u bob /bin/sh -c 'echo json-run; sleep 1'"
    aspty alice "sudo -u bob /bin/sh -c 'echo json-on-a-tty'"
    as alice "echo wrong | sudo -S -u bob /bin/true"
    cp /var/log/sudo.json /out/sudo.json
fi
cp -a /var/log/sudo-io /out/sudo-io
sudoreplay -d /var/log/sudo-io -l > /out/sudoreplay-list.txt 2>&1
# stream sizes as sudo wrote them and as they decompress (the ground truth for the byte counts)
(cd /var/log/sudo-io && find . -type f | sort | while read f; do
    case "$f" in */log|*/log.json|*/sequence) continue;; esac
    if gzip -t "$f" 2>/dev/null; then n=$(gzip -dc "$f" | wc -c); else n=$(wc -c < "$f"); fi
    echo "$f $n"
done) > /out/stream-bytes.txt
find /var/db/sudo /var/lib/sudo /run/sudo /var/run/sudo -type f -printf '%p %s %T@\n' 2>/dev/null | sort > /out/state-files.txt
cp -a /var/db/sudo /out/state-db 2>/dev/null; cp -a /var/lib/sudo /out/state-lib 2>/dev/null; cp -a /run/sudo /out/state-run 2>/dev/null
cp /etc/passwd /out/passwd
echo "$PRETTY_NAME $(uname -m)" > /out/os
