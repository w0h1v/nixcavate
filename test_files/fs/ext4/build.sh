#!/usr/bin/env bash
# Builds the ext2/ext3/ext4 test images and their ground truth with the real tools.
#
#   test_files/fs/ext4/build.sh            # run from anywhere; needs Docker
#   test_files/fs/ext4/build.sh bench DIR  # writes an uncommitted 100k-file image to DIR
#
# Each image is made with mke2fs, loop-mounted, populated with the same tree, listed with
# stat/readlink/sha256sum while mounted, unmounted, checked with e2fsck and compressed with zstd.
# Outputs per image NAME: NAME.img.zst, NAME.truth.zst (one tab-separated line per path, fields
# listed above `truth()`) and NAME.sha256 (sha256sum of every non-empty regular file).
set -eu  # no pipefail: `yes | head` ends with SIGPIPE

if [[ "${1:-}" != inside ]]; then
    here="$(cd "$(dirname "$0")" && pwd)"
    if [[ "${1:-}" == bench ]]; then
        out="$(cd "${2:?output dir}" && pwd)"
        exec docker run --rm --privileged --platform linux/amd64 -v "$here:/src:ro" -v "$out:/out" \
            debian:12 bash /src/build.sh inside bench
    fi
    exec docker run --rm --privileged --platform linux/amd64 -v "$here:/out" debian:12 bash /out/build.sh inside
fi

apt-get update -qq >/dev/null
apt-get install -y -qq e2fsprogs zstd >/dev/null 2>&1
mkdir -p /m

# The tree from the filesystem-reader brief. $1 is the filesystem block size.
populate() {
    local bs=$1
    cd /m
    mkdir -p a/b/c/d/e
    printf 'deep\n' > a/b/c/d/e/deep.txt
    : > empty
    printf 'hello world\n' > small.txt
    seq 1 40000 > medium.txt                       # ~229 KB: many blocks, distinct content
    head -c 30 /dev/zero | tr '\0' 'x' > tiny30    # fits in i_block (inline_data)
    seq 1 40 | head -c 100 > inline100             # overflows into system.data (inline_data)
    # Sparse: data at 0, 1 MiB and 100 MiB (triple-indirect territory with 1 KiB blocks).
    printf 'start' > sparse
    printf 'middle' | dd of=sparse bs=1 seek=$((1024 * 1024)) conv=notrunc status=none
    printf 'end' | dd of=sparse bs=1 seek=$((100 * 1024 * 1024)) conv=notrunc status=none
    # Every other block written: one extent per block (a deep extent tree with 1 KiB blocks).
    for i in $(seq 0 399); do
        yes "frag block $i" | head -c "$bs" | dd of=frag bs="$bs" seek=$((2 * i)) conv=notrunc status=none
    done
    # Preallocated (unwritten extents) with one write in the middle; plain ext2/3 cannot fallocate.
    if fallocate -l 65536 prealloc 2>/dev/null; then
        printf 'written' | dd of=prealloc bs=1 seek=8192 conv=notrunc status=none
    else
        rm -f prealloc
    fi
    mkdir bigdir
    (cd bigdir && for i in $(seq 0 2999); do : > "entry_$(printf %05d "$i")_with_a_somewhat_longer_name"; done)
    : > "$(printf 'long_%0250d' 7)"
    printf 'unicode\n' > 'héllo wörld 日本語.txt'
    : > "$(printf 'bad\xffname')"
    ln -s small.txt link_short
    ln -s "$(printf 'a/%.0s' $(seq 1 60))target_that_does_not_exist" link_long
    ln small.txt hardlink.txt
    mkfifo fifo
    printf 'owned\n' > owned; chown 1234:5678 owned
    printf 'big ids\n' > bigids; chown 70000:80000 bigids
    printf '#!/bin/sh\n' > setuid; chmod 4755 setuid
    mkdir sgid sticky; chmod 2750 sgid; chmod 1777 sticky
    chmod 600 small.txt
    printf 'future\n' > future; touch -d '2040-01-01T00:00:00.5Z' future
    printf 'past\n' > past; touch -d '1960-06-15T12:00:00Z' past
    touch -d '2001-02-03T04:05:06.123456789Z' small.txt
    touch -h -d '2010-10-10T10:10:10Z' link_short
    touch -d '2005-05-05T05:05:05Z' a/b/c
    sync
}

# path, file-type/mode hex, inode, links, size, uid, gid, atime, mtime, ctime, crtime, target
truth() {
    local name=$1
    cd /m
    find . -mindepth 1 -print0 | sort -z | while IFS= read -r -d '' p; do
        printf '%s\t%s\t%s\n' "${p#./}" \
            "$(stat -c '%f	%i	%h	%s	%u	%g	%.9X	%.9Y	%.9Z	%.9W' "$p")" \
            "$(readlink "$p" || true)"
    done | zstd -19 -q -f -o "/out/$name.truth.zst"
    find . -type f -size +0 -print0 | sort -z | xargs -0 sha256sum | sed 's#  \./#  #' > "/out/$name.sha256"
}

image() {
    local name=$1 mib=$2 bs=$3
    shift 3
    rm -f "/tmp/$name.img"
    # Stale bytes everywhere, so unwritten extents and uninitialized inode tables are not zeros.
    yes "stale data " | head -c $((mib * 1024 * 1024)) > "/tmp/$name.img"
    mke2fs -q -F -E nodiscard -b "$bs" "$@" "/tmp/$name.img"
    mount -o loop,noatime "/tmp/$name.img" /m
    populate "$bs"
    truth "$name"
    cd /
    umount /m
    e2fsck -fn "/tmp/$name.img" >/dev/null
    echo "== $name: frag extent levels: $(debugfs -R "ex /frag" "/tmp/$name.img" 2>/dev/null | awk "NR>1{print \$1}" | sort -u | tr "\\n" " ")"
    debugfs -R "stat /inline100" "/tmp/$name.img" 2>/dev/null | grep -i "inline data" || true
    dumpe2fs -h "/tmp/$name.img" 2>/dev/null | grep -E 'features|Inode size|Block size|Inodes per group|Blocks per group|Group descriptor size'
    zstd -19 -q -f "/tmp/$name.img" -o "/out/$name.img.zst"
}

if [[ "${2:-}" == bench ]]; then
    # 100 directories of 1000 empty files plus some small ones. Not committed.
    dd if=/dev/zero of=/out/bench.img bs=1M count=1024 status=none
    mke2fs -q -F -t ext4 -N 120000 /out/bench.img
    mount -o loop,noatime /out/bench.img /m
    for d in $(seq 0 99); do
        mkdir "/m/d$d"
        (cd "/m/d$d" && touch $(seq -f 'file_%04g' 0 999) && seq 1 50 | tee small_{1..20} >/dev/null)
    done
    find /m | wc -l
    umount /m
    exit 0
fi

# (1) default ext4 (64bit, flex_bg, metadata_csum, 256-byte inodes) with 4 KiB blocks
image ext4 16 4096 -t ext4 -N 6000
# (2) ext3: indirect block maps, 1 KiB blocks so the sparse file reaches the triple-indirect block
image ext3 16 1024 -t ext3 -N 6000
# (3) ext4 with inline data, 256-byte inodes and 1 KiB blocks
image ext4-inline 16 1024 -t ext4 -I 256 -O inline_data -N 6000
# (4) ext2 with 128-byte inodes (no creation time, no nanoseconds)
image ext2 16 2048 -t ext2 -I 128 -N 6000
# (5) 64bit + meta_bg with small groups so descriptors span more than one meta group
image ext4-metabg 24 1024 -t ext4 -O 64bit,meta_bg,^resize_inode -g 1024 -N 6000
