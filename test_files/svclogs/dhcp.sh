#!/bin/sh
# ISC dhcpd 4.4.3 on a Docker network answering a real dhclient in a second container: dhcpd.leases and dhclient.leases.
# Output: $1/dhcp/{dhcpd.leases,dhclient.leases}
set -eu
out="$1"; mkdir -p "$out/dhcp"
docker network rm nxdhcp >/dev/null 2>&1 || true
docker network create --platform linux/arm64 --subnet 10.77.0.0/24 --ip-range 10.77.0.0/28 nxdhcp >/dev/null 2>&1 || docker network create --subnet 10.77.0.0/24 nxdhcp >/dev/null
trap 'docker rm -f nxdhcpd nxdhclient >/dev/null 2>&1; docker network rm nxdhcp >/dev/null 2>&1' EXIT
docker run -d --name nxdhcpd --network nxdhcp --ip 10.77.0.2 --cap-add NET_ADMIN --cap-add NET_RAW --platform linux/arm64 debian:12 sh -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq isc-dhcp-server >/dev/null 2>&1
cat > /etc/dhcp/dhcpd.conf <<EOC
default-lease-time 600;
max-lease-time 7200;
authoritative;
subnet 10.77.0.0 netmask 255.255.255.0 {
  range 10.77.0.100 10.77.0.120;
  option routers 10.77.0.1;
  option domain-name-servers 10.77.0.1;
}
host reserved1 { hardware ethernet 02:42:0a:4d:00:09; fixed-address 10.77.0.50; }
EOC
touch /var/lib/dhcp/dhcpd.leases
echo ready; dhcpd -4 -f -d -cf /etc/dhcp/dhcpd.conf -lf /var/lib/dhcp/dhcpd.leases eth0 >/var/log/dhcpd.out 2>&1' >/dev/null
for i in $(seq 60); do docker logs nxdhcpd 2>&1 | grep -q ready && break; sleep 2; done; sleep 8
docker run -d --name nxdhclient --network nxdhcp --cap-add NET_ADMIN --cap-add NET_RAW --platform linux/arm64 debian:12 sh -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq isc-dhcp-client iproute2 >/dev/null 2>&1
ip link add dummy0 type dummy 2>/dev/null; ip link add link eth0 name mv0 type macvlan mode bridge 2>/dev/null; ip link set mv0 address 02:42:0a:4d:00:aa up
ip link add link eth0 name mv1 type macvlan mode bridge 2>/dev/null; ip link set mv1 address 02:42:0a:4d:00:09 up
dhclient -4 -v -lf /var/lib/dhcp/dhclient.leases -pf /tmp/dc.pid mv0 >/tmp/dc.out 2>&1
echo "send host-name \"client-two\";" > /tmp/c2.conf
dhclient -4 -v -cf /tmp/c2.conf -lf /var/lib/dhcp/dhclient1.leases -pf /tmp/dc1.pid mv1 >/tmp/dc1.out 2>&1
echo done; sleep 600' >/dev/null
for i in $(seq 90); do docker logs nxdhclient 2>&1 | grep -q '^done' && break; sleep 2; done
docker exec nxdhclient sh -c 'cat /tmp/dc.out /tmp/dc1.out' >&2 || true
docker exec nxdhclient sh -c 'cat /var/lib/dhcp/dhclient.leases' > "$out/dhcp/dhclient.leases"
docker exec nxdhclient sh -c 'cat /var/lib/dhcp/dhclient1.leases' > "$out/dhcp/dhclient1.leases"
docker exec nxdhcpd sh -c 'cat /var/lib/dhcp/dhcpd.leases' > "$out/dhcp/dhcpd.leases"
