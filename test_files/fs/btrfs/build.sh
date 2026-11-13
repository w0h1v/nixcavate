#!/bin/bash
# Builds the Btrfs test images and their ground truth with the real tools (btrfs-progs 6.14,
# the container's kernel). Run from the repository root:
#
#   docker run --rm --privileged --platform linux/arm64 -v "$PWD/test_files/fs/btrfs":/out \
#       debian:trixie bash /out/build.sh
#
# mkfs.btrfs needs at least 114 MiB (16 MiB with mixed block groups); the images are mostly
# zeros and are stored zstd-compressed.
#
#   default.img   mkfs defaults (16 KiB nodes, DUP metadata, no-holes): hard links, special
#                 files, a long symlink, holes, a preallocated range, a reflinked file edited in
#                 the middle, 3000 files in one directory, two names with the same directory
#                 hash, a nested subvolume (walked) and a read-only snapshot (not walked)
#   compress.img  zlib/, lzo/ and zstd/ written under `compress=<algorithm>` mounts: text over
#                 several 128 KiB extents, an inline compressed file, a hole, incompressible data
#   node4k.img    4 KiB nodes (a three-level tree); node64k.img: 64 KiB nodes
#   fedora.img    top level holding subvolumes `root` and `home`, default subvolume 5, fstab
#                 with `subvol=root` and `subvol=home`, a nested subvolume var/lib/machines
#   suse.img      `@` set as the default subvolume, `@home`, a nested `@/var/log`, `@/.snapshots`
#                 with a read-only snapshot of `@`, and a subvolume no fstab line mounts
#   arch.img      default subvolume 5 with `@`, `@home` (mounted by subvolid=), `@log`
#                 (`subvol=/@log`)
#   mixed.img     16 MiB, mixed block groups (-M), no-holes off: explicit hole extents
#
# Ground truth per image, from the mounted filesystem assembled as the system would mount it
# (root subvolume, then each fstab subvolume at its mount point; read-only snapshots pruned):
#   <name>.stat.tsv[.zst]  path, inode, raw mode (hex), uid, gid, size, links, atime, mtime,
#                          ctime, crtime (stat %.9X etc.)
#   <name>.sha256          sha256sum of every regular file
#   <name>.links.tsv       path and target of every symlink
set -euo pipefail

apt-get update -qq >/dev/null
apt-get install -y -qq btrfs-progs zstd python3 >/dev/null 2>&1
export TZ=UTC
OUT=/out
WORK=$(mktemp -d)
for i in $(seq 0 15); do [ -e /dev/loop$i ] || mknod /dev/loop$i b 7 $i; done

# Position-tagged, compressible text: every 64-byte record names its file and offset.
gen() { # gen <bytes> <tag>
    python3 -c 'import sys
n, t = int(sys.argv[1]), sys.argv[2]
o = "".join("%-12s%010d%s\n" % (t, i * 64, "." * 41) for i in range(n // 64 + 1))
sys.stdout.write(o[:n])' "$1" "$2"
}
rnd() { # rnd <bytes> <seed>: incompressible, reproducible
    python3 -c 'import sys, random
r = random.Random(sys.argv[2]); sys.stdout.buffer.write(r.randbytes(int(sys.argv[1])))' "$1" "$2"
}

# Two names with the same Btrfs directory hash (crc32c), found by search.
collision() {
    python3 - <<'EOF'
t = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
    t.append(c)
def h(s):
    c = 0xFFFFFFFE
    for b in s:
        c = t[(c ^ b) & 0xFF] ^ (c >> 8)
    return c
seen = {}
i = 0
while True:
    n = b"collide-%07d" % i
    k = h(n)
    if k in seen:
        print(seen[k].decode(), n.decode())
        break
    seen[k] = n
    i += 1
EOF
}

common() { # common <dir>: the tree shared by most images
    local d=$1
    cd "$d"
    mkdir -p etc a/b/c/d/e odd links special owners times
    echo btrfshost >etc/hostname
    printf 'root:x:0:0:root:/root:/bin/bash\n' >etc/passwd
    : >empty
    printf 'hello, btrfs\n' >small.txt
    gen 100000 large >a/b/large.bin
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
}

# Holes and preallocation: data at 0, 1 MiB and 3 MiB of a 4 MiB file; a preallocated
# 256 KiB range with 4 KiB written in its middle; a preallocated range past the end of a file.
holes() {
    gen 4096 hole0 >sparse.bin
    gen 4096 hole1 | dd of=sparse.bin bs=4096 seek=256 conv=notrunc status=none
    gen 4096 hole2 | dd of=sparse.bin bs=4096 seek=768 conv=notrunc status=none
    truncate -s 4M sparse.bin
    fallocate -l 262144 prealloc.bin
    gen 4096 prealloc | dd of=prealloc.bin bs=4096 seek=20 conv=notrunc status=none
    gen 10000 keepsize >keepsize.bin
    fallocate -n -o 10000 -l 100000 keepsize.bin
}

# A reflinked copy with its middle rewritten: the copy's extents point into the original's
# extent at an offset.
reflink() {
    gen 300000 shared >shared.bin
    sync
    cp --reflink=always shared.bin reflinked.bin
    gen 5000 rewritten | dd of=reflinked.bin bs=1 seek=150000 conv=notrunc status=none
}

many() { # many <dir> <count>
    mkdir -p "$1"
    (cd "$1" && for i in $(seq 1 "$2"); do : >"entry-with-a-longish-name-$i"; done)
    printf 'inside\n' >"$1/zz-content.txt"
}

truth() { # truth <mount> <name> [prune path...]
    local m=$1 name=$2
    shift 2
    local prune=()
    for p in "$@"; do prune+=(-path "./$p/*" -prune -o); done
    cd "$m"
    find . -mindepth 1 "${prune[@]}" -printf '%P\0' | sort -z |
        xargs -0 stat -c '%n	%i	%f	%u	%g	%s	%h	%.9X	%.9Y	%.9Z	%.9W' >"$OUT/$name.stat.tsv"
    find . -mindepth 1 "${prune[@]}" -type f -printf '%P\0' | sort -z | xargs -0 -r sha256sum >"$OUT/$name.sha256"
    find . -mindepth 1 "${prune[@]}" -type l -printf '%P\t%l\n' | sort >"$OUT/$name.links.tsv"
    cd /
}

finish() { # finish <image> <name>
    btrfs inspect-internal dump-super "$1" | grep -E '^(nodesize|sectorsize|incompat_flags|num_devices)' >"$OUT/$2.info"
    zstd -q -19 --long=27 -f "$1" -o "$OUT/$2.img.zst"
}

M=$WORK/mnt
mkdir -p "$M"

build_default() {
    local img=$WORK/default.img c1 c2
    read -r c1 c2 <<<"$(cd / && collision)"
    truncate -s 120M "$img"
    mkfs.btrfs -q "$img"
    mount -o loop "$img" "$M"
    (common "$M")
    cd "$M"
    holes
    reflink
    many many 3000
    mkdir collide
    echo first >"collide/$c1"
    echo second >"collide/$c2"
    printf '%s\n%s\n' "$c1" "$c2" >"$OUT/default.collision"
    btrfs -q subvolume create nested
    gen 5000 nested >nested/inside.txt
    mkdir snaps
    btrfs -q subvolume snapshot -r "$M" snaps/snap1
    echo after >after-snapshot.txt
    cd /
    umount "$M"
    mount -o loop,ro "$img" "$M"
    truth "$M" default snaps/snap1
    umount "$M"
    finish "$img" default
}

build_compress() {
    local img=$WORK/compress.img
    truncate -s 120M "$img"
    mkfs.btrfs -q "$img"
    for alg in zlib lzo zstd; do
        mount -o loop,compress=$alg "$img" "$M"
        mkdir -p "$M/$alg"
        cd "$M/$alg"
        echo "$alg" >../etc-$alg
        gen 700000 "$alg-big" >big.txt
        gen 1500 "$alg-inl" >inline.txt
        gen 200000 "$alg-hole" >holes.txt
        gen 100000 "$alg-hole2" | dd of=holes.txt bs=4096 seek=200 conv=notrunc status=none
        rnd 8000 "$alg" >random.bin
        gen 131072 "$alg-x" >exact.txt
        gen 300000 "$alg-edit" >edited.txt
        sync
        gen 3000 "$alg-patch" | dd of=edited.txt bs=1 seek=140000 conv=notrunc status=none
        cd /
        umount "$M"
    done
    mount -o loop "$img" "$M"
    mkdir -p "$M/etc"
    echo compresshost >"$M/etc/hostname"
    umount "$M"
    mount -o loop,ro "$img" "$M"
    truth "$M" compress
    umount "$M"
    finish "$img" compress
}

build_nodes() { # build_nodes <name> <nodesize>
    local img=$WORK/$1.img
    truncate -s 120M "$img"
    mkfs.btrfs -q -n "$2" "$img"
    mount -o loop "$img" "$M"
    (common "$M")
    cd "$M"
    many many 4000
    many many2 500
    cd /
    umount "$M"
    mount -o loop,ro "$img" "$M"
    truth "$M" "$1"
    umount "$M"
    finish "$img" "$1"
}

uuid_of() { blkid -o value -s UUID "$1"; }

build_fedora() {
    local img=$WORK/fedora.img
    truncate -s 120M "$img"
    mkfs.btrfs -q -L fedora "$img"
    mount -o loop "$img" "$M"
    btrfs -q subvolume create "$M/root"
    btrfs -q subvolume create "$M/home"
    (common "$M/root")
    local u
    u=$(uuid_of "$img")
    cat >"$M/root/etc/fstab" <<EOF
# /etc/fstab
UUID=$u /                       btrfs   subvol=root,compress=zstd:1 0 0
UUID=1111-2222          /boot/efi               vfat    umask=0077,shortname=winnt 0 2
UUID=$u /home                   btrfs   subvol=home,compress=zstd:1 0 0
EOF
    mkdir -p "$M/root/home" "$M/root/var/lib" "$M/root/var/log"
    btrfs -q subvolume create "$M/root/var/lib/machines"
    echo machine >"$M/root/var/lib/machines/inside"
    echo log >"$M/root/var/log/messages"
    mkdir -p "$M/home/alice"
    gen 20000 alice >"$M/home/alice/notes.txt"
    chown -R 1000:1000 "$M/home/alice"
    echo top >"$M/top-level-file"
    umount "$M"
    mount -o loop,ro,subvol=root "$img" "$M"
    mount -o loop,ro,subvol=home "$img" "$M/home"
    truth "$M" fedora
    umount "$M/home"
    umount "$M"
    finish "$img" fedora
}

build_suse() {
    local img=$WORK/suse.img
    truncate -s 120M "$img"
    mkfs.btrfs -q "$img"
    mount -o loop "$img" "$M"
    btrfs -q subvolume create "$M/@"
    btrfs -q subvolume create "$M/@home"
    btrfs -q subvolume create "$M/@unmounted"
    echo hidden >"$M/@unmounted/file"
    (common "$M/@")
    mkdir -p "$M/@/var" "$M/@/home"
    btrfs -q subvolume create "$M/@/var/log"
    echo log >"$M/@/var/log/messages"
    btrfs -q subvolume create "$M/@/.snapshots"
    mkdir "$M/@/.snapshots/1"
    echo '<snapshot><num>1</num></snapshot>' >"$M/@/.snapshots/1/info.xml"
    btrfs -q subvolume snapshot -r "$M/@" "$M/@/.snapshots/1/snapshot"
    echo changed-after-snapshot >>"$M/@/etc/hostname"
    mkdir -p "$M/@home/bob"
    echo bob >"$M/@home/bob/.profile"
    local u id
    u=$(uuid_of "$img")
    cat >"$M/@/etc/fstab" <<EOF
UUID=$u  /            btrfs  defaults,subvol=@  0  0
UUID=$u  /home        btrfs  subvol=@home  0  0
UUID=$u  /var/log     btrfs  subvol=@/var/log  0  0
UUID=$u  /.snapshots  btrfs  subvol=@/.snapshots  0  0
UUID=0000aaaa-0000-0000-0000-000000000000  /srv  btrfs  subvol=@home  0  0
EOF
    id=$(btrfs inspect-internal rootid "$M/@")
    btrfs subvolume set-default "$id" "$M"
    umount "$M"
    mount -o loop,ro "$img" "$M"
    mount -o loop,ro,subvol=@home "$img" "$M/home"
    mount -o loop,ro,subvol=@/.snapshots "$img" "$M/.snapshots"
    truth "$M" suse .snapshots/1/snapshot
    umount "$M/.snapshots"
    umount "$M/home"
    umount "$M"
    finish "$img" suse
}

build_arch() {
    local img=$WORK/arch.img
    truncate -s 120M "$img"
    mkfs.btrfs -q "$img"
    mount -o loop "$img" "$M"
    btrfs -q subvolume create "$M/@"
    btrfs -q subvolume create "$M/@home"
    btrfs -q subvolume create "$M/@log"
    (common "$M/@")
    mkdir -p "$M/@/home" "$M/@/var/log"
    echo pacman >"$M/@log/pacman.log"
    mkdir -p "$M/@home/carol"
    echo carol >"$M/@home/carol/file"
    local u home
    u=$(uuid_of "$img")
    home=$(btrfs inspect-internal rootid "$M/@home")
    cat >"$M/@/etc/fstab" <<EOF
# <file system> <dir> <type> <options> <dump> <pass>
UUID=$u	/	btrfs	rw,relatime,compress=zstd:3,subvol=/@	0 0
UUID=$u	/home	btrfs	rw,relatime,subvolid=$home	0 0
LABEL=nothing	/mnt/other	btrfs	subvol=/@log	0 0
/dev/vda2	/var/log	btrfs	rw,relatime,subvol=/@log	0 0
EOF
    umount "$M"
    mount -o loop,ro,subvol=@ "$img" "$M"
    mount -o loop,ro,subvolid="$home" "$img" "$M/home"
    mount -o loop,ro,subvol=@log "$img" "$M/var/log"
    truth "$M" arch
    umount "$M/var/log"
    umount "$M/home"
    umount "$M"
    finish "$img" arch
}

build_mixed() {
    local img=$WORK/mixed.img
    truncate -s 16M "$img"
    mkfs.btrfs -q -M -O ^no-holes "$img"
    mount -o loop "$img" "$M"
    cd "$M"
    mkdir -p etc a
    echo mixedhost >etc/hostname
    printf 'hello\n' >small.txt
    gen 50000 mixed >a/data.txt
    holes
    ln -s small.txt link
    ln small.txt a/hard
    cd /
    umount "$M"
    mount -o loop,ro "$img" "$M"
    truth "$M" mixed
    umount "$M"
    finish "$img" mixed
}

build_default
build_compress
build_nodes node4k 4096
build_nodes node64k 65536
build_fedora
build_suse
build_arch
build_mixed

# The listings of the images with many files are large and repetitive.
for f in "$OUT"/*.stat.tsv "$OUT"/*.sha256; do
    if [ "$(stat -c %s "$f")" -gt 65536 ]; then zstd -q -19 --rm -f "$f"; fi
done
ls -l "$OUT"
