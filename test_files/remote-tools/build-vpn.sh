#!/bin/bash
# Installs the real WireGuard tools, OpenVPN and ZeroTier in a throwaway privileged arm64
# container, configures them as an administrator would, lets each run (they cannot reach a peer)
# and copies the files and the tools' own output out. Example addresses and generated keys only.
# Usage: build-vpn.sh <output-dir>
set -uo pipefail
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
rm -f "$OUT"/*.truth.txt
docker rm -f l8s-vpn >/dev/null 2>&1
docker run -d --name l8s-vpn --privileged --platform linux/arm64 debian:12 sleep 3600 >/dev/null
x() { docker exec -i l8s-vpn bash -c "$1"; }
x 'apt-get update -qq && apt-get install -y -qq curl ca-certificates gnupg wireguard-tools openvpn iproute2 procps >/dev/null 2>&1; echo apt-done'
# WireGuard: wg-quick(8) layout. `wg-quick strip` is what the tool itself reads from the file.
x 'mkdir -p /etc/wireguard && cd /etc/wireguard && umask 077
SK=$(wg genkey); PK=$(echo $SK | wg pubkey); PEER=$(wg genkey | wg pubkey); PSK=$(wg genpsk)
echo "$SK" > /tmp/planted-private; echo "$PSK" > /tmp/planted-psk
cat > wg0.conf <<Y
[Interface]
Address = 10.8.0.2/24
PrivateKey = $SK
ListenPort = 51820
DNS = 10.8.0.1
PostUp = iptables -A FORWARD -i %i -j ACCEPT

[Peer]
PublicKey = $PEER
PresharedKey = $PSK
AllowedIPs = 10.8.0.0/24, 192.168.50.0/24
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
Y
wg-quick strip wg0; ip link add dev wg9 type wireguard && wg setconf wg9 <(wg-quick strip wg0) && wg show wg9 dump | sed "s/^[^\t]*\t[^\t]*\t/(keys elided)\t/" ' > "$OUT/wireguard.truth.txt" 2>&1
docker cp l8s-vpn:/tmp/planted-private "$OUT/wireguard.planted-private"; docker cp l8s-vpn:/tmp/planted-psk "$OUT/wireguard.planted-psk"
# OpenVPN client with an inline key and a credentials file; it fails to resolve its server and logs it.
x 'mkdir -p /etc/openvpn/client && cd /etc/openvpn/client && umask 077
printf "vpnuser\nPLANTED-OVPN-PASSWORD-0004\n" > creds.txt; printf -- "-----BEGIN CERTIFICATE-----\nPLANTED-OVPN-CA-0026\n-----END CERTIFICATE-----\n" > ca.crt
cat > office.conf <<Y
client
dev tun
proto udp
remote vpn.example.com 1194
remote backup.example.com 443 tcp
auth-user-pass /etc/openvpn/client/creds.txt
ca /etc/openvpn/client/ca.crt
cipher AES-256-GCM
status /var/log/openvpn-status.log 10
<cert>
-----BEGIN CERTIFICATE-----
PLANTED-OVPN-CERT-0006
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
PLANTED-OVPN-KEY-MATERIAL-0005
-----END PRIVATE KEY-----
</key>
Y
timeout 15 openvpn --config office.conf --verb 4 --log /var/log/openvpn.log --connect-retry-max 1 --resolv-retry 1 --connect-timeout 3; cat /var/log/openvpn.log | head -40' > "$OUT/openvpn.truth.txt" 2>&1
# ZeroTier: join a network (the daemon writes networks.d/<id>.conf even when it cannot reach it).
x 'curl -s https://raw.githubusercontent.com/zerotier/ZeroTierOne/main/doc/contact%40zerotier.com.gpg | gpg --dearmor > /usr/share/keyrings/zerotier.gpg
echo "deb [signed-by=/usr/share/keyrings/zerotier.gpg] http://download.zerotier.com/debian/bookworm bookworm main" > /etc/apt/sources.list.d/zerotier.list
apt-get update -qq && apt-get install -y -qq zerotier-one >/dev/null 2>&1; which zerotier-one' >> "$OUT/zerotier.truth.txt" 2>&1
x 'mkdir -p /dev/net; [ -e /dev/net/tun ] || mknod /dev/net/tun c 10 200; (zerotier-one -d); sleep 6; zerotier-cli join 8056c2e21c000001; zerotier-cli join 0123456789abcdef; sleep 6; zerotier-cli info; zerotier-cli listnetworks; ls -l /var/lib/zerotier-one /var/lib/zerotier-one/networks.d' >> "$OUT/zerotier.truth.txt" 2>&1
rm -rf "$OUT/tree"; mkdir -p "$OUT/tree/etc" "$OUT/tree/var/lib" "$OUT/tree/var/log"
docker cp l8s-vpn:/etc/wireguard "$OUT/tree/etc/wireguard"
docker cp l8s-vpn:/etc/openvpn "$OUT/tree/etc/openvpn"
docker cp l8s-vpn:/var/log/openvpn.log "$OUT/tree/var/log/openvpn.log"
mkdir -p "$OUT/tree/var/lib/zerotier-one"
docker cp l8s-vpn:/var/lib/zerotier-one/networks.d "$OUT/tree/var/lib/zerotier-one/networks.d"
docker cp l8s-vpn:/var/lib/zerotier-one/identity.public "$OUT/tree/var/lib/zerotier-one/identity.public"
docker rm -f l8s-vpn >/dev/null
echo done
