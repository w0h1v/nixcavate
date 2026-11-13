#!/bin/bash
# Builds solaris-vtoc.img.zst as root in a throwaway OmniOS (illumos) VM that has a blank 64 MiB
# second disk: an fdisk Solaris2 partition over that disk, a VTOC written by fmthard, UFS on
# slices 0 and 7 with a marker file each. Writes /root/vtoc/disk.img.zst (the fixture), and
# prtvtoc and fdisk (together solaris-vtoc.prtvtoc).
set -eu
export PATH=/usr/gnu/bin:/usr/bin:/usr/sbin
mkdir -p /root/vtoc /sm
d=$(echo | format 2>/dev/null | awk '/^ *[0-9]+\. c/ {print $2}' | while read x; do
    prtvtoc /dev/rdsk/${x}s2 >/dev/null 2>&1 && zpool status rpool | grep -q "$x" && continue; echo $x; done | head -1)
echo "disk $d"
fdisk -B /dev/rdsk/${d}p0
fdisk -W - /dev/rdsk/${d}p0 | grep -v '^\*' | grep -v '^$' > /root/vtoc/fdisk
prtvtoc /dev/rdsk/${d}s2 > /root/vtoc/prtvtoc.before 2>&1 || true
# slice tag flag start size (sectors, relative to the Solaris partition)
total=$(prtvtoc -h /dev/rdsk/${d}s2 | awk '$1 == 2 {print $5}')
printf '0 2 00 4096 32768\n1 3 01 36864 16384\n2 5 01 0 %s\n7 8 00 53248 40960\n' "$total" > /root/vtoc/fmthard.in
fmthard -s /root/vtoc/fmthard.in /dev/rdsk/${d}s2
prtvtoc /dev/rdsk/${d}s2 > /root/vtoc/prtvtoc
for s in 0 7; do
    echo y | newfs /dev/rdsk/${d}s$s > /dev/null 2>&1
    mount -F ufs /dev/dsk/${d}s$s /sm; echo "slice $s" > /sm/marker; umount /sm
done
dd if=/dev/rdsk/${d}p0 bs=1024k 2>/dev/null | zstd -19 -q -o /root/vtoc/disk.img.zst -f
ls -la /root/vtoc
