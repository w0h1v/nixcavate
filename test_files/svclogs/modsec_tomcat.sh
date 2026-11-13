#!/bin/sh
# Apache 2.4 + ModSecurity 2 + OWASP CRS driven with attack requests (serial modsec_audit.log), and Tomcat 10.1
# (catalina.out, catalina.<date>.log, localhost_access_log.<date>.txt). Debian 12 and the tomcat:10.1 image.
# Output: $1/modsec/modsec_audit.log, $1/tomcat/*
set -eu
out="$1"; mkdir -p "$out/modsec" "$out/tomcat"
here="$(cd "$(dirname "$0")" && pwd)"
docker run --rm --platform linux/arm64 -v "$here/modsec.conf:/nx-modsec.conf:ro" debian:12 sh -c '
exec 3>&1 1>&2
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq apache2 libapache2-mod-security2 modsecurity-crs curl >/dev/null 2>&1
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i "s/^SecRuleEngine DetectionOnly/SecRuleEngine On/" /etc/modsecurity/modsecurity.conf
sed -i "s/^SecAuditLogParts .*/SecAuditLogParts ABIJDEFHZ/" /etc/modsecurity/modsecurity.conf
sed -i "s/^SecAuditLogRelevantStatus .*/SecAuditLogRelevantStatus \"^(?:5|4(?!04))\"/" /etc/modsecurity/modsecurity.conf
cp /nx-modsec.conf /etc/apache2/conf-enabled/nx-modsec.conf
echo ok > /var/www/html/ok.html
apachectl configtest >&2
apachectl start >&2; sleep 2
ls /usr/share/modsecurity-crs/rules 2>&1 | head -3 >&2
curl -s -o /dev/null "http://127.0.0.1/ok.html"
curl -s -o /dev/null "http://127.0.0.1/?id=1%27%20OR%20%271%27=%271"
curl -s -o /dev/null "http://127.0.0.1/?testparam=nxblock"
curl -s -o /dev/null -A "sqlmap/1.7" "http://127.0.0.1/index.php?q=1%20UNION%20SELECT%20password%20FROM%20users"
curl -s -o /dev/null "http://127.0.0.1/../../etc/passwd"
curl -s -o /dev/null -d "x=<script>alert(1)</script>" "http://127.0.0.1/post"
curl -s -o /dev/null "http://127.0.0.1/missing-page"
sleep 1
mkdir -p /o; cp /var/log/apache2/modsec_audit.log /o/; ls /var/log/apache2 >&2; cd /o; tar cf - . >&3' | tar -C "$out/modsec" -xf -
docker rm -f nxtomcat >/dev/null 2>&1 || true
docker run -d --name nxtomcat --platform linux/arm64 --entrypoint sh tomcat:10.1 -c 'cp -r webapps.dist/. webapps/; catalina.sh start; sleep 3000' >/dev/null
# The image has no curl: plain HTTP over bash's /dev/tcp.
get() { docker exec nxtomcat bash -c "exec 3<>/dev/tcp/127.0.0.1/8080; printf '%s %s HTTP/1.1\\r\\nHost: localhost\\r\\nUser-Agent: curl-test\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\n' '$1' '$2' >&3; cat <&3 >/dev/null" 2>/dev/null; }
for i in $(seq 60); do get GET / && break; sleep 2; done
for u in /docs/ /nosuch /manager/html "/?a=1&b=2"; do get GET "$u"; done
get POST /docs/x
# The access log valve buffers; it flushes on its background timer.
sleep 20
docker exec nxtomcat sh -c 'cd /usr/local/tomcat/logs && tar cf - .' | tar -C "$out/tomcat" -xf -
docker rm -f nxtomcat >/dev/null
