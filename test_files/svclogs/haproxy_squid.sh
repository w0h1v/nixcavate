#!/bin/sh
# HAProxy 2.6 (http and tcp logs through rsyslog) and Squid 5.7 (native and combined access logs, cache.log), Debian 12.
# Output: $1/haproxy/haproxy.log, $1/squid/{access.log,combined.log,cache.log}
set -eu
out="$1"; mkdir -p "$out/haproxy" "$out/squid"
docker run --rm --platform linux/arm64 debian:12 sh -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq haproxy rsyslog python3 curl squid >/dev/null 2>&1
cat > /etc/rsyslog.d/10-haproxy.conf <<EOC
module(load="imudp")
input(type="imudp" address="127.0.0.1" port="514")
local0.* /var/log/haproxy.log
EOC
rm -f /etc/rsyslog.d/49-haproxy.conf
rsyslogd 2>/dev/null; sleep 1
mkdir /www; echo hello > /www/index.html; echo data > /www/a.txt
(cd /www && python3 -m http.server 8000 --bind 127.0.0.1 >/dev/null 2>&1 &)
(cd /www && python3 -m http.server 8001 --bind 127.0.0.1 >/dev/null 2>&1 &)
cat > /etc/haproxy/haproxy.cfg <<EOC
global
    log 127.0.0.1:514 local0
defaults
    log global
    mode http
    option httplog
    timeout connect 2s
    timeout client 5s
    timeout server 5s
frontend web
    bind 127.0.0.1:8080
    default_backend app
backend app
    server s1 127.0.0.1:8000
    server s2 127.0.0.1:8001
backend dead
    server d1 127.0.0.1:9999
frontend tcpin
    bind 127.0.0.1:8081
    mode tcp
    option tcplog
    default_backend tcpapp
backend tcpapp
    mode tcp
    server t1 127.0.0.1:8000
frontend broken
    bind 127.0.0.1:8082
    default_backend dead
EOC
haproxy -D -f /etc/haproxy/haproxy.cfg; sleep 1
for i in 1 2 3 4; do curl -s -o /dev/null http://127.0.0.1:8080/index.html; done
curl -s -o /dev/null http://127.0.0.1:8080/missing?x=1
curl -s -o /dev/null -d "user=alice&pw=x" -H "Host: shop.example.test" http://127.0.0.1:8080/login
curl -s -o /dev/null -A "evil agent/1.0" "http://127.0.0.1:8080/../../etc/passwd"
curl -s -o /dev/null http://127.0.0.1:8082/x
curl -s -o /dev/null http://127.0.0.1:8081/a.txt
curl -s -o /dev/null --max-time 1 http://127.0.0.1:8081/index.html
sleep 2
# Squid with an extra combined-format log and port 8000 allowed.
sed -i "s/^acl Safe_ports port 80.*/acl Safe_ports port 80\nacl Safe_ports port 8000/" /etc/squid/squid.conf
printf "access_log daemon:/var/log/squid/access.log squid\naccess_log daemon:/var/log/squid/combined.log combined\n" >> /etc/squid/squid.conf
squid -N -f /etc/squid/squid.conf >/dev/null 2>&1 & sleep 5
export http_proxy=http://127.0.0.1:3128
curl -s -o /dev/null http://127.0.0.1:8000/index.html
curl -s -o /dev/null http://127.0.0.1:8000/index.html
curl -s -o /dev/null http://127.0.0.1:8000/missing
curl -s -o /dev/null http://127.0.0.1:8001/a.txt
curl -s -o /dev/null -A "scanner/2 (x)" http://127.0.0.1:8000/a.txt
curl -s -o /dev/null -x http://127.0.0.1:3128 -p http://127.0.0.1:22/
curl -s -o /dev/null -x http://127.0.0.1:3128 http://203.0.113.9:8000/
sleep 2
squid -k shutdown; sleep 3
mkdir /o; cp /var/log/haproxy.log /var/log/squid/access.log /var/log/squid/combined.log /var/log/squid/cache.log /o/
cd /o; tar cf - .' > "$out/raw.tar"
cd "$out" && tar -xf raw.tar -C haproxy haproxy.log && tar -xf raw.tar -C squid access.log combined.log cache.log && rm raw.tar
