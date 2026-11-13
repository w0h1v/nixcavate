#!/bin/sh
# Runs inside a privileged container: real password changes through pam_pwhistory (remember=5)
# fill /etc/security/opasswd; the hash types are listed with awk as the reference.
if command -v apt-get >/dev/null; then
    apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq libpam-pwquality >/dev/null 2>&1
fi
mkdir -p /out
for u in alice bob; do useradd -m $u 2>/dev/null || adduser --disabled-password --gecos '' $u; done
change() { # user password algorithm
    cat > /etc/pam.d/chpasswd <<PAM
password requisite pam_pwquality.so retry=1
password required pam_pwhistory.so remember=5 use_authtok
password required pam_unix.so $3 use_authtok
PAM
    echo "$1:$2" | chpasswd
}
change alice 'first-Pass-1' sha512
change alice 'second-Pass-2' sha512
change alice 'third-Pass-3' md5
change alice 'fourth-Pass-4' sha512
change bob 'only-Pass-1' sha512
if grep -q yescrypt /usr/lib/*/security/pam_unix.so /lib/*/security/pam_unix.so 2>/dev/null; then
    change alice 'fifth-Pass-5' yescrypt
    change bob 'second-Pass-2' yescrypt
fi
cp /etc/security/opasswd /out/opasswd
cp /etc/passwd /out/passwd
# reference: per line the user, the uid, the count and the type prefix of each hash
awk -F: '{ n = split($4, h, ","); t = ""; for (i = 1; i <= n; i++) { split(h[i], p, "$"); t = t (i > 1 ? "," : "") "$" p[2] "$" } print $1, $2, $3, t }' /etc/security/opasswd > /out/reference.txt
echo "$PRETTY_NAME $(uname -m)" > /out/os
