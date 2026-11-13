#!/bin/bash
# Builds the ZFS test images and their ground truth with the real tools: OpenZFS 2.2
# (zfsutils-linux and the kernel module of an Ubuntu 24.04 cloud image, in a throwaway
# virtual machine: a container's kernel has no ZFS). Run as root inside that machine:
#
#   sudo bash build.sh /out [image names]
#
# Every pool is 64 to 256 MiB of mostly zeros; the images are stored zstd-compressed.
#
#   default.img   one file vdev, defaults (lz4, 128 KiB records, ashift 12 from -o ashift):
#                 hard links, special files, a long symlink (in the spill block), holes, 3000
#                 files in one directory (a fat ZAP), long and non-ASCII names, owners up to
#                 4000000001, times before 1970 and with nanoseconds, xattr=sa attributes
#   compress.img  child datasets with compression off, lzjb, gzip-1, gzip-9, zle, lz4, zstd
#                 and zstd-19: text over several records, holes, random data, a rewritten middle
#   records.img   recordsize 512 (a three-level block tree), 128K and 1M (large_blocks),
#                 ashift 9, copies=2, dnodesize=auto (large dnodes) and xattr=on directories
#   v28.img       pool version 28 with a version-4 file system: znode_phys_t attributes, no
#                 system attributes, no feature flags, lzjb
#   layout.img    a FreeBSD-style root pool `zroot`: boot environments ROOT/default (bootfs)
#                 and ROOT/old, canmount=off containers usr and var with children inheriting
#                 their mountpoints, a legacy dataset mounted by /etc/fstab, a snapshot, a
#                 clone, a zvol, an encrypted dataset, a canmount=noauto dataset
#   mirror.img    GPT disk with two partitions holding a two-way mirror
#   stripe.img    GPT disk with two partitions, each a top-level vdev
#   raidz1.img    GPT disk with three partitions in RAID-Z1; raidz2.img: four in RAID-Z2
#   dirty.img     a pool with a log vdev, copied while imported with sync=always writes not
#                 yet committed: the intent log holds records
#
# Ground truth per image, from a read-only import (`zpool import -o readonly=on -R`) mounted
# as the system would (the bootfs dataset at /, then `zfs mount -a`, then the fstab line):
#   <name>.stat.tsv[.zst]  path, inode, raw mode (hex), uid, gid, size, links, atime, mtime,
#                          ctime, crtime (stat %.9X etc.; crtime is 0 where statx has none)
#   <name>.sha256          sha256sum of every regular file
#   <name>.links.tsv       path and target of every symlink
#   <name>.info            `zpool get` of the version, ashift and active features
#   layout.mounted         `zfs list` of what the read-only import mounted
set -euo pipefail

export TZ=UTC
OUT=${1:-/out}
mkdir -p "$OUT"
WORK=$(mktemp -d /var/tmp/zfsbuild.XXXX)
T=/mnt/truth
mkdir -p $T

gen() { # gen <bytes> <tag>: position-tagged, compressible text
    python3 -c 'import sys
n, t = int(sys.argv[1]), sys.argv[2]
o = "".join("%-12s%010d%s\n" % (t, i * 64, "." * 41) for i in range(n // 64 + 1))
sys.stdout.write(o[:n])' "$1" "$2"
}
rnd() { # rnd <bytes> <seed>: incompressible, reproducible
    python3 -c 'import sys, random
r = random.Random(sys.argv[2]); sys.stdout.buffer.write(r.randbytes(int(sys.argv[1])))' "$1" "$2"
}

common() { # common <dir>: the tree shared by most images
    local d=$1
    cd "$d"
    mkdir -p etc a/b/c/d/e odd links special owners times
    echo zfshost >etc/hostname
    printf 'root:x:0:0:root:/root:/bin/sh\n' >etc/passwd
    : >empty
    printf 'hello, zfs\n' >small.txt
    gen 300000 large >a/b/large.bin
    gen 4096 deep >a/b/c/d/e/deep.txt
    printf 'long name\n' >"odd/$(printf 'L%.0s' $(seq 1 255))"
    printf 'unicode\n' >"odd/café-日本語-ü.txt"
    echo x >"odd/with space"
    ln -s ../small.txt links/short
    ln -s "$(printf 'dir/%.0s' $(seq 1 940))end" links/long
    ln small.txt links/hard1
    ln small.txt a/hard2
    mkfifo special/fifo
    mknod special/null c 1 3
    mknod special/loop b 7 0
    echo x >special/setuid
    chmod 4755 special/setuid
    echo x >special/none
    chmod 0000 special/none
    echo x >owners/big
    chown 4000000000:4000000001 owners/big
    echo x >owners/nobody
    chown 65534:65534 owners/nobody
    echo x >times/y1960
    touch -d '1960-01-02 03:04:05.5 UTC' times/y1960
    echo x >times/y2200
    touch -d '2200-01-02 03:04:05 UTC' times/y2200
    echo x >times/nanos
    touch -d '2024-03-10 01:02:03.123456789 UTC' times/nanos
    touch -a -d '2001-02-03 04:05:06.987654321 UTC' times/nanos
    touch -h -d '2010-10-10 10:10:10 UTC' links/short
    python3 -c 'import os; os.setxattr("small.txt", "user.note", b"an extended attribute")'
    cd /
}

holes() { # holes <dir>: data at 0, 1 MiB and 3 MiB of a 4 MiB file
    gen 4096 hole0 >"$1/sparse.bin"
    gen 4096 hole1 | dd of="$1/sparse.bin" bs=4096 seek=256 conv=notrunc status=none
    gen 4096 hole2 | dd of="$1/sparse.bin" bs=4096 seek=768 conv=notrunc status=none
    truncate -s 4M "$1/sparse.bin"
}

many() { # many <dir> <count>
    mkdir -p "$1"
    (cd "$1" && for i in $(seq 1 "$2"); do : >"entry-with-a-longish-name-$i"; done)
    printf 'inside\n' >"$1/zz-content.txt"
}

truth() { # truth <name>: the tree under $T
    local name=$1
    cd $T
    find . -mindepth 1 -printf '%P\0' | sort -z |
        xargs -0 stat -c '%n	%i	%f	%u	%g	%s	%h	%.9X	%.9Y	%.9Z	%.9W' >"$OUT/$name.stat.tsv"
    find . -mindepth 1 -type f -printf '%P\0' | sort -z | xargs -0 -r sha256sum >"$OUT/$name.sha256"
    find . -mindepth 1 -type l -printf '%P\t%l\n' | sort >"$OUT/$name.links.tsv"
    cd /
}

# import <pool> <device or directory>...: read-only, every dataset that mounts at boot mounted.
import() {
    local pool=$1 args=() dev
    shift
    for dev in "$@"; do args+=(-d "$dev"); done
    zpool import -o readonly=on -R $T -N "${args[@]}" "$pool"
    zfs mount -a
}

# export <pool>: the import may still be busy for a moment (udev, zed).
export_pool() {
    for _ in 1 2 3 4 5 6 7 8 9 10; do zpool export "$1" 2>/dev/null && return; sleep 2; done
    zpool export "$1"
}

# The mountpoint directories an import made under $T, once nothing is mounted there.
clean_truth() {
    find $T -mindepth 1 -depth -type d -empty -delete
}

finish() { # finish <pool> <name> <image>
    zpool get -H -o property,value version,ashift "$1" >"$OUT/$2.info"
    zpool get -H -o property,value all "$1" | awk '$1 ~ /^feature@/ && $2 == "active" {print}' >>"$OUT/$2.info"
    export_pool "$1"
    clean_truth
    zstd -q -19 --long=27 -f "$3" -o "$OUT/$2.img.zst"
}

build_default() {
    local d=$WORK/default
    mkdir -p "$d"
    truncate -s 128M "$d/default.img"
    zpool create -o ashift=12 -O xattr=sa -O atime=off -m /dpool dpool "$d/default.img"
    common /dpool
    holes /dpool
    many /dpool/many 3000
    gen 1000000 rewrite >/dpool/rewritten.bin
    sync
    gen 5000 patch | dd of=/dpool/rewritten.bin bs=1 seek=300000 conv=notrunc status=none
    export_pool dpool
    import dpool "$d"
    truth default
    finish dpool default "$d/default.img"
}

build_compress() {
    local d=$WORK/compress
    mkdir -p "$d"
    truncate -s 128M "$d/compress.img"
    zpool create -o ashift=12 cpool "$d/compress.img"
    for alg in off lzjb gzip-1 gzip-9 zle lz4 zstd zstd-19; do
        zfs create -o compression=$alg "cpool/$alg"
        local m=/cpool/$alg
        gen 700000 "$alg-big" >$m/big.txt
        gen 1500 "$alg-small" >$m/small.txt
        gen 200000 "$alg-hole" >$m/holes.txt
        gen 100000 "$alg-hole2" | dd of=$m/holes.txt bs=4096 seek=200 conv=notrunc status=none
        rnd 20000 "$alg" >$m/random.bin
        head -c 200000 /dev/zero >$m/zeros.bin
        printf 'z%.0s' $(seq 1 3000) >$m/runs.txt
        gen 131072 "$alg-x" >$m/exact.txt
        gen 300000 "$alg-edit" >$m/edited.txt
        sync
        gen 3000 "$alg-patch" | dd of=$m/edited.txt bs=1 seek=140000 conv=notrunc status=none
    done
    export_pool cpool
    import cpool "$d"
    truth compress
    finish cpool compress "$d/compress.img"
}

build_records() {
    local d=$WORK/records
    mkdir -p "$d"
    truncate -s 192M "$d/records.img"
    zpool create -o ashift=9 rpool2 "$d/records.img"
    zfs create -o recordsize=512 -o compression=off rpool2/r512
    zfs create -o recordsize=128K rpool2/r128k
    zfs create -o recordsize=1M -o compression=zstd rpool2/r1m
    zfs create -o copies=2 rpool2/copies
    zfs create -o dnodesize=auto -o xattr=sa rpool2/bigdnode
    zfs create -o dnodesize=legacy -o xattr=on rpool2/dirxattr
    for ds in r512 r128k r1m copies bigdnode dirxattr; do
        local m=/rpool2/$ds
        gen 1100000 "$ds-big" >$m/big.txt
        gen 10000 "$ds-a" >$m/sparse.bin
        gen 10000 "$ds-b" | dd of=$m/sparse.bin bs=1 seek=900000 conv=notrunc status=none
        truncate -s 3000000 $m/sparse.bin
        ln -s "$(printf 'x%.0s' $(seq 1 1000))" $m/longlink
        mkdir $m/dir
        for i in $(seq 1 40); do echo "$ds $i" >"$m/dir/f$i"; done
        python3 -c 'import os, sys; os.setxattr(sys.argv[1], "user.big", b"v" * 3000)' $m/big.txt
    done
    export_pool rpool2
    import rpool2 "$d"
    truth records
    finish rpool2 records "$d/records.img"
}

build_v28() {
    local d=$WORK/v28
    mkdir -p "$d"
    truncate -s 96M "$d/v28.img"
    zpool create -o version=28 -O version=4 -O compression=lzjb -m /oldpool oldpool "$d/v28.img"
    common /oldpool
    holes /oldpool
    many /oldpool/many 600
    export_pool oldpool
    import oldpool "$d"
    truth v28
    finish oldpool v28 "$d/v28.img"
}

build_layout() {
    local d=$WORK/layout
    mkdir -p "$d"
    truncate -s 256M "$d/layout.img"
    echo "example passphrase" >$WORK/pass
    zpool create -o ashift=12 -O compression=lz4 -O atime=off -O mountpoint=/zroot -R /mnt/build zroot "$d/layout.img"
    zfs create -o mountpoint=none zroot/ROOT
    zfs create -o mountpoint=/ -o canmount=noauto zroot/ROOT/default
    zfs create -o mountpoint=/ -o canmount=noauto zroot/ROOT/old
    zpool set bootfs=zroot/ROOT/default zroot
    zfs create -o mountpoint=/usr -o canmount=off zroot/usr
    zfs create zroot/usr/home
    zfs create zroot/usr/src
    zfs create -o mountpoint=/var -o canmount=off zroot/var
    zfs create zroot/var/log
    zfs create -o exec=off zroot/var/mail
    zfs create -o mountpoint=legacy zroot/data
    zfs create -o canmount=noauto -o mountpoint=/opt zroot/noauto
    zfs create -o mountpoint=/secret -o encryption=on -o keyformat=passphrase \
        -o keylocation=file://$WORK/pass zroot/secret
    zfs create -V 8M zroot/vol
    # Mounted again in boot order, so each mountpoint directory is made where the system has it.
    zfs unmount -a
    zfs mount zroot/ROOT/default
    zfs mount -a
    local B=/mnt/build
    common $B
    mkdir -p $B/data
    printf '# Device\tMountpoint\tFStype\tOptions\tDump\tPass#\n/dev/gpt/swap0\tnone\tswap\tsw\t0\t0\nzroot/data\t/data\tzfs\trw\t0\t0\n' >$B/etc/fstab
    echo 'beside the usr datasets' >$B/usr/in-root.txt
    mkdir -p $B/usr/home/alice
    echo alice >$B/usr/home/alice/.profile
    chown -R 1001:1001 $B/usr/home/alice
    echo source >$B/usr/src/Makefile
    echo 'Jan  1 00:00:00 host syslogd: restart' >$B/var/log/messages
    zfs snapshot zroot/var/log@before
    echo 'after the snapshot' >>$B/var/log/messages
    zfs clone zroot/var/log@before zroot/logclone
    echo 'written in the clone' >$B/zroot/logclone/clone.txt
    echo 'pool top' >$B/zroot/top.txt
    mount -t zfs zroot/data $B/data
    echo 'legacy dataset' >$B/data/file.txt
    umount $B/data
    zfs mount zroot/noauto
    echo 'not mounted at boot' >$B/opt/hidden.txt
    zfs unmount zroot/noauto
    echo 'secret' >$B/secret/file.txt
    mkdir -p /mnt/oldbe
    mount -t zfs -o zfsutil zroot/ROOT/old /mnt/oldbe
    mkdir -p /mnt/oldbe/etc
    echo old-boot-environment >/mnt/oldbe/etc/hostname
    umount /mnt/oldbe
    export_pool zroot
    # Without the key, the encrypted dataset stays unmounted: `zfs mount -a` says so and fails.
    zpool import -o readonly=on -R $T -N -d "$d" zroot
    zfs mount zroot/ROOT/default
    zfs mount -a || true
    mount -t zfs zroot/data $T/data
    zfs list -H -o name,mountpoint,canmount,mounted -t filesystem,volume >"$OUT/layout.mounted"
    truth layout
    umount $T/data
    finish zroot layout "$d/layout.img"
}

# A GPT disk with <count> partitions of <mib> MiB on a loop device; prints the device.
gptdisk() { # gptdisk <image> <count> <mib>
    truncate -s $(($2 * $3 + 2))M "$1"
    sgdisk -Z "$1" >/dev/null
    for i in $(seq 1 "$2"); do sgdisk -n "$i:0:+$3M" -t "$i:BF01" "$1" >/dev/null; done
    local dev
    dev=$(losetup -fP --show "$1")
    udevadm settle
    for _ in $(seq 1 50); do [ -b "${dev}p$2" ] && break; sleep 0.2; done
    echo "$dev"
}

build_multi() { # build_multi <name> <pool> <count> <vdev layout words...>
    local name=$1 pool=$2 count=$3 d=$WORK/$1
    shift 3
    mkdir -p "$d"
    local dev parts=()
    dev=$(gptdisk "$d/$name.img" "$count" 64)
    for i in $(seq 1 "$count"); do parts+=("${dev}p$i"); done
    zpool create -o ashift=12 -m /$pool $pool "$@" "${parts[@]}"
    mkdir -p /$pool/etc
    echo "$name" >/$pool/etc/hostname
    gen 1500000 "$name-big" >/$pool/big.txt
    rnd 100000 "$name" >/$pool/random.bin
    holes /$pool
    many /$pool/many 300
    export_pool $pool
    import $pool "${parts[@]}"
    truth "$name"
    zpool get -H -o property,value version,ashift "$pool" >"$OUT/$name.info"
    export_pool $pool
    clean_truth
    losetup -d "$dev"
    zstd -q -19 --long=27 -f "$d/$name.img" -o "$OUT/$name.img.zst"
}

build_dirty() {
    local d=$WORK/dirty
    mkdir -p "$d"
    truncate -s 128M "$d/dirty.img"
    truncate -s 64M "$d/dirty-log.img"
    zpool create -o ashift=12 -m /dirtypool dirtypool "$d/dirty.img" log "$d/dirty-log.img"
    mkdir -p /dirtypool/etc
    echo committed >/dirtypool/etc/hostname
    gen 50000 committed >/dirtypool/committed.txt
    zpool sync dirtypool
    local old
    old=$(cat /sys/module/zfs/parameters/zfs_txg_timeout)
    echo 600 >/sys/module/zfs/parameters/zfs_txg_timeout
    sleep 6
    zfs set sync=always dirtypool
    gen 20000 logged >/dirtypool/logged.txt
    echo appended >>/dirtypool/committed.txt
    # Copied with the pool imported: these writes are only in the intent log.
    cp --sparse=always "$d/dirty.img" "$d/copy.img"
    cp --sparse=always "$d/dirty-log.img" "$d/copy-log.img"
    echo "$old" >/sys/module/zfs/parameters/zfs_txg_timeout
    export_pool dirtypool
    mkdir -p "$d/c"
    mv "$d/copy.img" "$d/c/dirty.img"
    mv "$d/copy-log.img" "$d/c/dirty-log.img"
    import dirtypool "$d/c"
    truth dirty
    zpool get -H -o property,value version,ashift dirtypool >"$OUT/dirty.info"
    export_pool dirtypool
    clean_truth
    zstd -q -19 --long=27 -f "$d/c/dirty.img" -o "$OUT/dirty.img.zst"
    zstd -q -19 --long=27 -f "$d/c/dirty-log.img" -o "$OUT/dirty-log.img.zst"
}

# Every image, or those named after the output folder.
shift || true
for name in "${@:-default compress records v28 layout mirror stripe raidz1 raidz2 dirty}"; do
    for n in $name; do
        case $n in
        mirror) build_multi mirror mpool 2 mirror ;;
        stripe) build_multi stripe spool 2 ;;
        raidz1) build_multi raidz1 zpool1 3 raidz1 ;;
        raidz2) build_multi raidz2 zpool2 4 raidz2 ;;
        *) "build_$n" ;;
        esac
    done
done

# The listings of the images with many files are large and repetitive.
for f in "$OUT"/*.stat.tsv "$OUT"/*.sha256; do
    if [ "$(stat -c %s "$f")" -gt 65536 ]; then zstd -q -19 --rm -f "$f"; fi
done
rm -rf "$WORK"
ls -l "$OUT"
