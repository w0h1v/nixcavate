#!/bin/sh
# Builds disk.img with the real LVM tools: a GPT disk with two LVM2 physical volumes in one
# volume group. The logical volume `root` (ext4, a small Linux host) has two segments, the
# first on the second PV and the second on the first PV, and `big.txt` crosses the boundary.
# `swap` is a second logical volume with no filesystem.
#
#   docker run --rm --privileged -v /dev:/dev -v "$PWD/test_files/image/lvm":/w debian:13 sh /w/build.sh
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq lvm2 e2fsprogs gdisk zstd >/dev/null 2>&1
cfg='devices{use_devicesfile=0} activation{udev_sync=0 udev_rules=0} backup{backup=0 archive=0}'
dd if=/dev/zero of=/w/disk.img bs=1M count=16 status=none
sgdisk -n 1:2048:14335 -t 1:8e00 -n 2:14336:28671 -t 2:8e00 /w/disk.img >/dev/null
a=$(losetup -f --show -o $((2048*512)) --sizelimit $((12288*512)) /w/disk.img)
b=$(losetup -f --show -o $((14336*512)) --sizelimit $((12288*512)) /w/disk.img)
lvm pvcreate -q --config "$cfg" --metadatasize 128k "$a" "$b" >/dev/null
lvm vgcreate -q --config "$cfg" -s 1M vg0 "$a" "$b" >/dev/null
lvm lvcreate -q --config "$cfg" -Zn -Wn -l 1 -n swap vg0 "$a" >/dev/null
lvm lvcreate -q --config "$cfg" -Zn -Wn -l 2 -n root vg0 "$b" >/dev/null
lvm lvextend -q --config "$cfg" -l +2 vg0/root "$a" >/dev/null
dmsetup mknodes

r=$(mktemp -d)
mkdir -p $r/etc $r/var/log
echo lvmhost > $r/etc/hostname
printf 'PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"\n' > $r/etc/os-release
printf 'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n' > $r/etc/passwd
printf 'Etc/UTC\n' > $r/etc/timezone
printf '2024-03-10T01:02:03.000000+00:00 lvmhost sshd[42]: Accepted password for alice from 203.0.113.9 port 50000 ssh2\n' > $r/var/log/secure
awk 'BEGIN { for (i = 0; i < 60000; i++) printf "%07d the quick brown fox jumps over the lazy dog\n", i }' > $r/big.txt
touch -d '2024-03-10 01:02:03 UTC' $r/var/log/secure $r/etc/passwd $r/big.txt
mkfs.ext4 -q -b 1024 -O ^has_journal -d $r -E root_owner=0:0 /dev/mapper/vg0-root
sha256sum < $r/big.txt | cut -d' ' -f1 > /w/big.sha256
lvm lvs --config "$cfg" --noheadings -o lv_name,seg_start_pe,seg_size_pe,devices vg0
sync
lvm vgchange -q --config "$cfg" -an vg0 >/dev/null
losetup -d "$a" "$b"
zstd -q -19 -f /w/disk.img -o /w/disk.img.zst && rm /w/disk.img
ls -la /w
