#!/bin/sh
# vsftpd 3.0.3 (vsftpd.log and xferlog, dual_log_enable) driven by ftplib; Samba 4.17 (log.smbd, per-client log,
# full_audit lines in syslog) driven by smbclient. Debian 12.
# Output: $1/vsftpd/{vsftpd.log,xferlog}, $1/samba/{log.smbd,log.client,audit.log}
set -eu
out="$1"; mkdir -p "$out/vsftpd" "$out/samba"
docker run --rm --platform linux/arm64 debian:12 sh -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq vsftpd python3 >/dev/null 2>&1
useradd -m alice; echo alice:Example-Pass-1 | chpasswd
echo "hello" > /home/alice/up.txt; head -c 20000 /dev/zero > /home/alice/big.bin; chown alice /home/alice/*
cat > /etc/vsftpd.conf <<EOC
listen=YES
listen_ipv6=NO
local_enable=YES
write_enable=YES
dual_log_enable=YES
xferlog_enable=YES
xferlog_std_format=YES
vsftpd_log_file=/var/log/vsftpd.log
xferlog_file=/var/log/xferlog
log_ftp_protocol=NO
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
seccomp_sandbox=NO
EOC
mkdir -p /var/run/vsftpd/empty
(vsftpd /etc/vsftpd.conf &) ; sleep 2
python3 - >&2 <<EOP
import ftplib, io
f = ftplib.FTP("127.0.0.1"); f.login("alice", "Example-Pass-1")
f.retrbinary("RETR big.bin", lambda b: None)
f.storbinary("STOR new file.txt", io.BytesIO(b"x" * 500))
f.storlines("STOR ascii.txt", io.BytesIO(b"line\n"))
f.delete("up.txt"); f.mkd("sub"); f.rmd("sub"); f.quit()
for u, p in (("alice", "wrong"), ("nosuch", "x")):
    try: ftplib.FTP("127.0.0.1").login(u, p)
    except Exception as e: print("expected", e)
try: ftplib.FTP("127.0.0.1").login("anonymous", "a@b")
except Exception as e: print("expected", e)
EOP
sleep 2
mkdir /o; cp /var/log/vsftpd.log /var/log/xferlog /o/; cd /o; tar cf - .' | tar -C "$out/vsftpd" -xf -
docker run --rm --platform linux/arm64 debian:12 sh -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq samba smbclient rsyslog >/dev/null 2>&1
useradd -M -s /usr/sbin/nologin alice; printf "Example-Pass-1\nExample-Pass-1\n" | smbpasswd -a -s alice >/dev/null
mkdir -p /srv/share; chown alice /srv/share; echo content > /srv/share/doc.txt; chown alice /srv/share/doc.txt
cat > /etc/samba/smb.conf <<EOC
[global]
  workgroup = WORKGROUP
  log level = 1 auth:3
  log file = /var/log/samba/log.%m
  max log size = 1000
  map to guest = never
  vfs objects = full_audit
  full_audit:prefix = %u|%I|%S
  full_audit:success = connect disconnect openat unlinkat renameat mkdirat
  full_audit:failure = connect
  full_audit:facility = local5
  full_audit:priority = notice
[share]
  path = /srv/share
  read only = no
  valid users = alice
EOC
echo "local5.* /var/log/samba/audit.log" > /etc/rsyslog.d/samba.conf; mkdir -p /var/log/samba
rsyslogd 2>/dev/null; sleep 1; smbd -D; sleep 3
smbclient //127.0.0.1/share -U alice%Example-Pass-1 -c "put /etc/hostname up.txt; get doc.txt /tmp/doc; rename up.txt moved.txt; mkdir d1; rmdir d1; del moved.txt" >&2
smbclient //127.0.0.1/share -U alice%wrong -c ls >&2 || true
smbclient //127.0.0.1/share -U nosuch%x -c ls >&2 || true
smbclient -L 127.0.0.1 -N >&2 || true
sleep 2
mkdir /o; cp /var/log/samba/log.smbd /var/log/samba/audit.log /o/; ls /var/log/samba >&2; cp /var/log/samba/log.127.0.0.1 /o/log.client 2>/dev/null || cp /var/log/samba/log.* /o/ 2>/dev/null; cd /o; tar cf - .' | tar -C "$out/samba" -xf -
