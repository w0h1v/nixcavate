#!/bin/sh
# Postfix + Dovecot (Debian 12) and Exim 4 (Debian 12) driven by real clients; syslog by rsyslog.
# Output: $1/postfix-dovecot/mail.log, $1/exim/mainlog, $1/truth.txt (counts from the daemons' own side).
set -eu
out="$1"; mkdir -p "$out/postfix-dovecot" "$out/exim"
docker run --rm --platform linux/arm64 debian:12 sh -c '
export DEBIAN_FRONTEND=noninteractive
echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
echo "postfix postfix/mailname string mail.example.test" | debconf-set-selections
apt-get update -qq >/dev/null && apt-get install -y -qq postfix dovecot-imapd dovecot-pop3d rsyslog python3 >/dev/null 2>&1
useradd -m -s /bin/bash alice; echo alice:Example-Pass-1 | chpasswd
useradd -m -s /bin/bash bob;   echo bob:Example-Pass-2 | chpasswd
postconf -e "mydestination = mail.example.test, localhost" "inet_interfaces = loopback-only" "smtpd_sasl_type = dovecot" "smtpd_sasl_path = private/auth" "smtpd_sasl_auth_enable = yes" "smtpd_tls_security_level = none" "smtpd_relay_restrictions = permit_sasl_authenticated, reject_unauth_destination" "disable_dns_client_requests = 1" "smtp_host_lookup = native"
cat >> /etc/dovecot/conf.d/10-master.conf <<EOC
service auth {
 unix_listener /var/spool/postfix/private/auth {
 mode = 0660
 user = postfix
 group = postfix
 }
}
EOC
sed -i "s/^#disable_plaintext_auth.*/disable_plaintext_auth = no/" /etc/dovecot/conf.d/10-auth.conf
sed -i "s/^auth_mechanisms.*/auth_mechanisms = plain login/" /etc/dovecot/conf.d/10-auth.conf
echo "mail_location = mbox:~/mail:INBOX=/var/mail/%u" > /etc/dovecot/conf.d/99-nx.conf
echo "auth_verbose = yes
auth_verbose_passwords = no
mail_debug = no" >> /etc/dovecot/conf.d/99-nx.conf
echo "mail.* action(type=\"omfile\" file=\"/var/log/mail.classic\" template=\"RSYSLOG_TraditionalFileFormat\")" > /etc/rsyslog.d/classic.conf
rsyslogd; sleep 1; postfix start >/dev/null 2>&1; sleep 3; dovecot; sleep 3
python3 - >&2 <<EOP
import smtplib, imaplib, poplib, time, socket
def send(frm, to, subj, user=None, pw=None, n=1):
    s = smtplib.SMTP("127.0.0.1", 25)
    if user: s.login(user, pw)
    for i in range(n):
        try: s.sendmail(frm, to, "Subject: %s\r\n\r\nhello\r\n" % subj)
        except Exception as e: print("send failed", e)
    s.quit()
send("bob@example.test", ["alice@mail.example.test"], "one")
send("carol@example.test", ["alice@mail.example.test", "bob@mail.example.test"], "two")
send("nobody@example.test", ["ghost@mail.example.test"], "three")
send("mallory@example.test", ["x@elsewhere.invalid"], "relay")
try:
    s = smtplib.SMTP("127.0.0.1", 25); s.login("alice", "Example-Pass-1"); s.sendmail("alice@mail.example.test", ["bob@mail.example.test"], "Subject: authed\r\n\r\nhi\r\n"); s.quit()
except Exception as e: print("auth send", e)
try:
    s = smtplib.SMTP("127.0.0.1", 25); s.login("alice", "wrong-pass")
except Exception as e: print("expected failure", e)
try:
    s = smtplib.SMTP("127.0.0.1", 25); s.login("nosuchuser", "x")
except Exception as e: print("expected failure", e)
time.sleep(3)
m = imaplib.IMAP4("127.0.0.1"); m.login("alice", "Example-Pass-1"); m.select(); m.logout()
m = imaplib.IMAP4("127.0.0.1"); m.login("bob", "Example-Pass-2"); m.logout()
try: imaplib.IMAP4("127.0.0.1").login("alice", "badbadbad")
except Exception as e: print("expected failure", e)
p = poplib.POP3("127.0.0.1"); p.user("bob"); p.pass_("Example-Pass-2"); p.quit()
time.sleep(5)
EOP
postqueue -f >/dev/null 2>&1; sleep 3
mkdir -p /out; cp /var/log/mail.log /var/log/mail.classic /out/
# Dovecot writing its own file (log_path) instead of syslog.
doveadm stop; sleep 1
echo "log_path = /var/log/dovecot.log" >> /etc/dovecot/conf.d/99-nx.conf
dovecot; sleep 2
python3 - >&2 <<EOP
import imaplib, poplib
m = imaplib.IMAP4("127.0.0.1"); m.login("alice", "Example-Pass-1"); m.logout()
try: imaplib.IMAP4("127.0.0.1").login("bob", "badbadbad")
except Exception as e: print("expected failure", e)
p = poplib.POP3("127.0.0.1"); p.user("alice"); p.pass_("Example-Pass-1"); p.quit()
EOP
sleep 2; cp /var/log/dovecot.log /out/
cd /out; tar cf - .' | tar -C "$out/postfix-dovecot" -xf -
