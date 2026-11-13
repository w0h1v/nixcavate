#!/bin/sh
# BIND 9.18 query log and fail2ban 1.0.2 (sshd jail, dummy action) with real sshd failures, Debian 12.
# Output: $1/named/query.log, $1/fail2ban/fail2ban.log
set -eu
out="$1"; mkdir -p "$out/named" "$out/fail2ban"
docker run --rm --platform linux/arm64 debian:12 sh -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq bind9 bind9-dnsutils >/dev/null 2>&1
mkdir -p /var/log/named; chown bind /var/log/named
cat > /etc/bind/named.conf.options <<EOC
options { directory "/var/cache/bind"; listen-on { 127.0.0.1; }; listen-on-v6 { none; }; recursion yes; allow-query { any; }; dnssec-validation no; forwarders {}; };
logging {
  channel q { file "/var/log/named/query.log" versions 3 size 5m; print-time yes; print-severity yes; print-category yes; severity dynamic; };
  category queries { q; };
};
EOC
cat >> /etc/bind/named.conf.local <<EOC
zone "example.test" { type master; file "/etc/bind/db.example.test"; };
EOC
cat > /etc/bind/db.example.test <<EOC
\$TTL 60
@ IN SOA ns.example.test. root.example.test. 1 60 60 60 60
@ IN NS ns.example.test.
ns IN A 192.0.2.53
www IN A 192.0.2.10
@ IN MX 10 mail.example.test.
@ IN TXT "v=spf1 -all"
EOC
chown -R bind /etc/bind; named -u bind; sleep 2
rndc querylog on 2>/dev/null || true
dig @127.0.0.1 www.example.test A +short >/dev/null
dig @127.0.0.1 www.example.test AAAA >/dev/null
dig @127.0.0.1 example.test MX >/dev/null
dig @127.0.0.1 example.test TXT +tcp >/dev/null
dig @127.0.0.1 nosuch.example.test A >/dev/null
dig @127.0.0.1 -x 192.0.2.10 >/dev/null
dig @127.0.0.1 www.example.test A +nocookie +norecurse >/dev/null
dig @127.0.0.1 example.test ANY >/dev/null
sleep 1
mkdir -p /o; cp /var/log/named/query.log /o/; cd /o; tar cf - .' | tar -C "$out/named" -xf -
docker run --rm --platform linux/arm64 debian:12 sh -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq fail2ban openssh-server rsyslog sshpass iproute2 >/dev/null 2>&1
useradd -m alice; echo alice:Example-Pass-1 | chpasswd
mkdir -p /run/sshd; rsyslogd 2>/dev/null; /usr/sbin/sshd; sleep 1
cat > /etc/fail2ban/jail.local <<EOC
[DEFAULT]
banaction = dummy
ignoreself = false
ignoreip =
backend = polling
[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
findtime = 60
bantime = 30
EOC
touch /var/log/auth.log
rm -f /var/log/fail2ban.log
fail2ban-client start >/dev/null 2>&1 || (fail2ban-server -b >/dev/null 2>&1 &); sleep 4
for i in 1 2 3 4; do sshpass -p wrong ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 alice@127.0.0.1 true 2>/dev/null; done
for i in 1 2; do sshpass -p wrong ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password nosuchuser@127.0.0.1 true 2>/dev/null; done
sleep 6
fail2ban-client status sshd >&2
fail2ban-client set sshd unbanip 127.0.0.1 >&2; sleep 2
mkdir -p /o; cp /var/log/fail2ban.log /var/log/auth.log /o/; cd /o; tar cf - .' | tar -C "$out/fail2ban" -xf -
