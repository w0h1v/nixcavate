#!/bin/sh
# Runs inside a privileged container (see generate.sh): real failed logins through libpam
# against whichever failure-counting module the distribution has, then the real listing
# tools' output. Writes everything to /out.
. /etc/os-release
if command -v apt-get >/dev/null; then
    apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq python3 >/dev/null 2>&1
else
    (yum install -y -q python3 shadow-utils || dnf install -y -q python3) >/dev/null 2>&1
fi
mkdir -p /out
for u in alice bob carol; do useradd -m $u 2>/dev/null || adduser --disabled-password --gecos '' $u; echo "$u:S3cret-$u" | chpasswd; done
try() { python3 /pamtry.py nxtest "$@" >> /out/attempts.txt 2>&1; }
: > /out/attempts.txt
LIBDIR=$(dirname "$(find / -name pam_unix.so 2>/dev/null | head -1)")
mkdir -p /var/run/faillock
if [ -e "$LIBDIR/pam_faillock.so" ] && command -v faillock >/dev/null; then
    cat > /etc/pam.d/nxtest <<PAM
auth required pam_faillock.so preauth deny=3 unlock_time=600 audit
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail deny=3 unlock_time=600
auth sufficient pam_faillock.so authsucc deny=3
auth required pam_deny.so
account required pam_unix.so
PAM
    try alice wrong1 rhost=203.0.113.9
    try alice wrong2 rhost=203.0.113.9
    try alice wrong3 tty=pts/3
    try bob wrong1 rhost=198.51.100.77
    try bob wrong2 rhost=198.51.100.77
    try bob wrong3 rhost=198.51.100.77
    try bob wrong4 rhost=198.51.100.77
    try bob "S3cret-bob" rhost=198.51.100.77    # refused: locked out
    ls -la /var/run/faillock /run/faillock > /out/ls.txt 2>&1
    mkdir -p /out/faillock && cp -a /var/run/faillock/. /out/faillock/
    # carol: locked by two failures, then the lock expires (unlock_time=1) and one more failure
    # follows, which leaves the earlier entries invalid
    sed 's/deny=3 unlock_time=600/deny=2 unlock_time=1/' /etc/pam.d/nxtest > /etc/pam.d/nxshort
    python3 /pamtry.py nxshort carol wrong1 rhost=192.0.2.5 >> /out/attempts.txt 2>&1
    python3 /pamtry.py nxshort carol wrong2 tty=ssh >> /out/attempts.txt 2>&1
    sleep 3
    python3 /pamtry.py nxshort carol wrong3 rhost=192.0.2.5 >> /out/attempts.txt 2>&1
    rm -rf /out/faillock; mkdir -p /out/faillock && cp -a /var/run/faillock/. /out/faillock/
    for u in alice bob carol; do faillock --user $u > /out/faillock-$u.txt 2>&1; done
    faillock > /out/faillock-all.txt 2>&1
fi
if [ -e "$LIBDIR/pam_tally2.so" ]; then
    cat > /etc/pam.d/nxtest <<PAM
auth required pam_tally2.so deny=3 unlock_time=600 onerr=fail
auth required pam_unix.so
account required pam_tally2.so
account required pam_unix.so
PAM
    try alice wrong1 rhost=203.0.113.9
    try alice wrong2 rhost=203.0.113.9
    try alice wrong3 tty=pts/3
    try bob wrong1 rhost=198.51.100.77
    try bob wrong2 rhost=198.51.100.77
    try bob wrong3 rhost=198.51.100.77
    try bob wrong4 rhost=198.51.100.77
    cp /var/log/tallylog /out/tallylog
    { id -u alice; id -u bob; } > /out/uids.txt
    for u in alice bob root; do pam_tally2 -u $u > /out/tally2-$u.txt 2>&1; done
    pam_tally2 > /out/tally2-all.txt 2>&1
fi
if [ -e "$LIBDIR/pam_tally.so" ]; then
    # the older module that keeps shadow's faillog
    cat > /etc/pam.d/nxtest <<PAM
auth required pam_tally.so deny=3 onerr=fail
auth required pam_unix.so
account required pam_tally.so
account required pam_unix.so
PAM
    : > /out/attempts-tally.txt
    rm -f /var/log/faillog /var/log/tallylog
    try alice wrong1 rhost=203.0.113.9
    try alice wrong2 tty=pts/3
    try bob wrong1 rhost=198.51.100.77
    try bob wrong2 rhost=198.51.100.77
    try bob wrong3 rhost=198.51.100.77
    ls -la /var/log/faillog > /out/faillog-ls.txt 2>&1
    cp /var/log/faillog /out/faillog 2>/dev/null
fi
# shadow's own faillog tool, when present (also sets the limit and lock time, which no module does)
if command -v faillog >/dev/null; then
    faillog -u alice -m 5 -l 600 2>/dev/null
    faillog -a > /out/faillog-a.txt 2>&1
    cp /var/log/faillog /out/faillog.shadow 2>/dev/null
fi
cp /etc/passwd /out/passwd
echo "$PRETTY_NAME $(uname -m)" > /out/os
