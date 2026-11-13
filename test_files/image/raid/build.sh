#!/bin/bash
# Builds the software RAID fixtures with the real tools (mdadm, sgdisk, mkfs.ext4, lvm2) on a
# machine whose kernel has md (the kernel of the usual macOS container runtimes does not: use a
# Linux VM with a stock Debian 13 kernel). Each fixture is a sparse disk image, zstd compressed:
#
#   <name>.img.zst          one disk whose partitions are the members (type fd00)
#   <name>-d1.img.zst ...   one disk per member, for the arrays split over several image files
#   <name>.sha256           sha256 of every file of the filesystem, taken from a real mount of the
#                           assembled array (`sha256sum` of the tree, paths relative to /)
#   <name>.mdadm            `mdadm --detail` and `--examine` of the array, the reference
#
# Every filesystem holds the same small Linux host: hostname `raidhost`, an os-release, passwd,
# a log, and `big.txt`, 1.56 MB of position-dependent text that crosses chunk and stripe
# boundaries of every array here. Run as root:  OUT=/some/dir bash build.sh
# (There is no linear fixture: the Debian kernel has no md-linear, so no real kernel gave the truth.)
set -eu
export DEBIAN_FRONTEND=noninteractive
W=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$W}
mkdir -p /etc/mdadm && echo 'AUTO -all' > /etc/mdadm/mdadm.conf
modprobe md_mod raid0 raid1 raid456 raid10 2>/dev/null || true
cfg='devices{use_devicesfile=0} activation{udev_sync=0 udev_rules=0} backup{backup=0 archive=0}'

tree=$(mktemp -d)
mkdir -p $tree/etc $tree/var/log
echo raidhost > $tree/etc/hostname
printf 'PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"\n' > $tree/etc/os-release
printf 'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n' > $tree/etc/passwd
printf 'Etc/UTC\n' > $tree/etc/timezone
printf '2024-03-10T01:02:03.000000+00:00 raidhost sshd[42]: Accepted password for alice from 203.0.113.9 port 50000 ssh2\n' > $tree/var/log/secure
awk 'BEGIN { for (i = 0; i < 30000; i++) printf "%07d the quick brown fox jumps over the lazy dog\n", i }' > $tree/big.txt
touch -d '2024-03-10 01:02:03 UTC' $tree/var/log/secure $tree/etc/passwd $tree/big.txt

LOOPS=()
cleanup() { mdadm --stop --scan 2>/dev/null || true; for l in "${LOOPS[@]:-}"; do [ -n "$l" ] && losetup -d "$l" 2>/dev/null || true; done; LOOPS=(); }
trap cleanup EXIT

# make NAME MODE LEVEL "MIB MIB ..." "mdadm args" [lvm]
# MODE is parts (one disk, a partition per member) or disks (one disk per member). The kernel's
# loop devices here have no partition scan, so each member is a loop device on its byte range.
make() {
    local name=$1 mode=$2 level=$3 sizes=$4 extra=$5 lvm=${6:-}
    local members=() n=0 s
    if [ "$mode" = parts ]; then
        local total=2 start=2048 end
        for s in $sizes; do total=$((total + s + 1)); done
        local img=$OUT/$name.img; rm -f $img; truncate -s ${total}M $img
        for s in $sizes; do
            n=$((n + 1)); end=$((start + s * 2048 - 1))
            sgdisk -n $n:$start:$end -t $n:fd00 $img >/dev/null
            local lo; lo=$(losetup -f --show -o $((start * 512)) --sizelimit $(((end - start + 1) * 512)) $img)
            LOOPS+=($lo); members+=($lo)
            start=$((end + 1 + 2048))
        done
    else
        for s in $sizes; do
            n=$((n + 1))
            local img=$OUT/$name-d$n.img; rm -f $img; truncate -s $((s + 3))M $img
            sgdisk -n 1:2048:$((2048 + s * 2048 - 1)) -t 1:fd00 $img >/dev/null
            local lo; lo=$(losetup -f --show -o $((2048 * 512)) --sizelimit $((s * 2048 * 512)) $img)
            LOOPS+=($lo); members+=($lo)
        done
    fi
    mdadm --create /dev/md/$name --run --force --level=$level --raid-devices=$n --homehost=fixture $extra "${members[@]}" >/dev/null
    mdadm --wait /dev/md/$name 2>/dev/null || true
    local dev=/dev/md/$name
    if [ -n "$lvm" ]; then
        lvm pvcreate -q --config "$cfg" --metadatasize 128k $dev >/dev/null
        lvm vgcreate -q --config "$cfg" -s 1M vgr $dev >/dev/null
        lvm lvcreate -q --config "$cfg" -Zn -Wn -l 100%FREE -n root vgr >/dev/null 2>&1
        dmsetup mknodes; dev=/dev/mapper/vgr-root
    fi
    mkfs.ext4 -q -b 1024 -O ^has_journal -d $tree -E root_owner=0:0 $dev
    mkdir -p /mnt/$name && mount -o ro $dev /mnt/$name
    (cd /mnt/$name && find . -type f ! -path './lost+found/*' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sed 's# \./# /#') > $OUT/$name.sha256
    umount /mnt/$name
    { mdadm --detail /dev/md/$name; for m in "${members[@]}"; do mdadm --examine $m; done; } > $OUT/$name.mdadm 2>&1 || true
    [ -n "$lvm" ] && lvm vgchange -q --config "$cfg" -an vgr >/dev/null
    mdadm --stop /dev/md/$name >/dev/null 2>&1 || mdadm --stop --scan
    for l in "${LOOPS[@]}"; do losetup -d $l; done; LOOPS=()
    if [ "$mode" = parts ]; then zstd -q -19 -f --long=27 $OUT/$name.img -o $OUT/$name.img.zst; rm $OUT/$name.img
    else for ((i = 1; i <= n; i++)); do zstd -q -19 -f --long=27 $OUT/$name-d$i.img -o $OUT/$name-d$i.img.zst; rm $OUT/$name-d$i.img; done; fi
    echo "built $name"
}

make raid1-12   parts 1  "4 4" "--metadata=1.2 --name=r1"
make raid1-090  parts 1  "4 4" "--metadata=0.90"
make raid1-10   parts 1  "4 4" "--metadata=1.0 --name=r1"
make raid1-11   parts 1  "4 4" "--metadata=1.1 --name=r1"
make raid0-64k  parts 0  "4 4" "--metadata=1.2 --chunk=64 --name=r0"
make raid0-512k parts 0  "4 4" "--metadata=1.2 --chunk=512 --name=r0"
make raid0-zones-orig parts 0 "3 5 7" "--metadata=1.2 --chunk=64 --layout=original --name=z0"
make raid0-zones-alt  parts 0 "3 5 7" "--metadata=1.2 --chunk=64 --layout=alternate --name=z0"
make raid5-ls   parts 5  "4 4 4" "--metadata=1.2 --chunk=64 --layout=left-symmetric --name=r5"
make raid5-la   parts 5  "4 4 4" "--metadata=1.2 --chunk=64 --layout=left-asymmetric --name=r5"
make raid5-rs   parts 5  "4 4 4" "--metadata=1.2 --chunk=64 --layout=right-symmetric --name=r5"
make raid5-ra   parts 5  "4 4 4" "--metadata=1.2 --chunk=64 --layout=right-asymmetric --name=r5"
make raid5-090  parts 5  "4 4 4 4" "--metadata=0.90 --chunk=128"
make raid4      parts 4  "4 4 4" "--metadata=1.2 --chunk=64 --name=r4"
make raid6      parts 6  "4 4 4 4" "--metadata=1.2 --chunk=64 --name=r6"
make raid10-n2  parts 10 "4 4 4 4" "--metadata=1.2 --chunk=64 --layout=n2 --name=r10"
make raid10-n2-3 parts 10 "4 4 4" "--metadata=1.2 --chunk=64 --layout=n2 --name=r10"
make raid10-f2  parts 10 "4 4" "--metadata=1.2 --chunk=64 --layout=f2 --name=r10"
make raid1-lvm  parts 1  "8 8" "--metadata=1.2 --name=rl" lvm
make m-raid1    disks 1  "4 4" "--metadata=1.2 --name=m1"
make m-raid5    disks 5  "4 4 4" "--metadata=1.2 --chunk=64 --name=m5"
make m-raid0    disks 0  "4 4" "--metadata=1.0 --chunk=64 --name=m0"
ls -l $OUT/*.zst | awk '{s+=$5} END {print s " bytes in all"}'
