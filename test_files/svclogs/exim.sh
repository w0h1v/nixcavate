#!/bin/sh
# Exim 4.96 (Debian 12) driven by smtplib: deliveries, failures, bounces, a local message. The Debian build did not
# advertise AUTH here, so the `A=` and authenticator lines are not in this fixture. Output: $1/exim/mainlog
set -eu
out="$1"; mkdir -p "$out/exim"
docker run --rm --platform linux/arm64 debian:12 sh -c '
export DEBIAN_FRONTEND=noninteractive
echo "exim4-config exim4/dc_eximconfig_configtype select internet site; mail is sent and received directly using SMTP" | debconf-set-selections
echo "exim4-config exim4/dc_local_interfaces string 127.0.0.1" | debconf-set-selections
echo "exim4-config exim4/dc_other_hostnames string mail.example.test" | debconf-set-selections
apt-get update -qq >/dev/null && apt-get install -y -qq exim4-daemon-light python3 >/dev/null 2>&1
useradd -m alice; useradd -m bob
f=/etc/exim4/conf.d/auth/30_exim4-config_examples
sed -i "/^#plain_server:/,/^#   server_set_id/ s/^#//" $f
sed -i "/^#login_server:/,/^#   server_set_id/ s/^#//" $f
sed -i "/server_advertise_condition/d" $f
python3 - <<EOP
import crypt
open("/etc/exim4/passwd","w").write("".join("%s:{crypt}%s\n" % (u, crypt.crypt(p, crypt.mksalt(crypt.METHOD_SHA512))) for u,p in [("alice","Example-Pass-1"),("bob","Example-Pass-2")]))
EOP
chown root:Debian-exim /etc/exim4/passwd; chmod 640 /etc/exim4/passwd
sed -i "s/^dc_use_split_config.*/dc_use_split_config=\"true\"/" /etc/exim4/update-exim4.conf.conf
update-exim4.conf 2>&1 | tail -2
(exim4 -bdf -q30m >/dev/null 2>&1 &); sleep 3
python3 - >&2 <<EOP
import smtplib, time
def one(f,to,auth=None):
    s=smtplib.SMTP("127.0.0.1",25,timeout=15); s.ehlo("client.example.test")
    if auth:
        try: s.login(*auth)
        except Exception as e: print("auth", e)
    try: s.sendmail(f,to,"Subject: t\r\n\r\nbody\r\n")
    except Exception as e: print("send", e)
    try: s.quit()
    except Exception: pass
one("bob@example.test",["alice@mail.example.test"])
one("carol@example.test",["alice@mail.example.test","bob@mail.example.test"])
one("x@example.test",["ghost@mail.example.test"])
one("alice@mail.example.test",["bob@mail.example.test"],("alice","Example-Pass-1"))
one("alice@mail.example.test",["bob@mail.example.test"],("alice","bad-password"))
one("m@example.test",["x@elsewhere.invalid"])
time.sleep(4)
EOP
echo "Subject: local" | exim4 -f root@mail.example.test alice
sleep 3
cat /var/log/exim4/mainlog' > "$out/exim/mainlog"
