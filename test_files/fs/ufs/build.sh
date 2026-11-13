#!/bin/sh
# Builds the UFS test images and their ground truth with FreeBSD's own tools. Run as root in a
# throwaway FreeBSD 14 VM (the images here came from the official 14.5-RELEASE cloud image):
#
#   sh build.sh OUTDIR        # writes NAME.img.zst, NAME.truth.zst, NAME.sha256 per image
#   sh build.sh OUTDIR matrix # uncommitted: the larger matrix (MATRIX_MIB MiB images, raw)
#   sh build.sh OUTDIR labels # partitioned disks: NAME.img.zst and NAME.gpart (gpart show)
#
# newfs images: newfs on a vnode-backed md device, mounted, filled with the tree below,
# listed with stat/readlink/sha256sum while mounted, unmounted and checked with fsck_ffs.
# makefs images (big-endian ones too): one tree on a scratch UFS2 mount is packed by makefs
# twice, little- and big-endian; the kernel cannot mount the big-endian one, so the truth of
# both is the mount of the little-endian image (makefs lays out both the same way).
# NAME.truth.zst: one tab-separated line per path: path, mode (hex), inode, links, size, uid,
# gid, atime, mtime, ctime, birthtime (seconds.nanoseconds), symlink target.
# NAME.sha256: sha256sum of every non-empty regular file under 300 MiB (the larger ones are
# sparse files with a few bytes far out, checked by targeted reads).
set -eu
export LC_ALL=C
out=$(cd "${1:?output dir}" && pwd)
mode=${2:-fixtures}
w=/var/tmp/ufsbuild
mkdir -p $w /m /src
# File content: a numbered line sequence (distinct per file through its first line, and it
# compresses, unlike random bytes).
[ -f $w/seq ] || jot 1000000 > $w/seq
gen() { # gen BYTES NAME > file
    [ "$1" -eq 0 ] || (echo "$2"; cat $w/seq $w/seq) | head -c "$1"
}

# fill DIR UFSVERSION BSIZE FSIZE SCALE: the edge-case tree. SCALE 1 is the small fixture tree;
# larger values add more entries (the matrix).
fill() {
    d=$1 v=$2 bs=$3 fs=$4 scale=$5
    cd "$d"
    ptr=$((v == 1 ? 4 : 8))
    nindir=$((bs / ptr))
    inl=$((v == 1 ? 60 : 120))
    mkdir -p etc var/log big deep odd links special times owners frag
    printf 'root:*:0:0:Charlie &:/root:/bin/sh\n' > etc/passwd
    echo ufshost > etc/hostname
    echo 'Nov 12 10:00:00 ufshost kernel: hello' > var/log/messages
    # A big directory: empty entries (no blocks), then long names and many directories.
    mkdir manyfiles; (cd manyfiles && jot -w f%d $((2500 * scale)) | xargs touch)
    mkdir longnames; for i in $(jot $((40 * scale))); do echo "$i" > "longnames/$(printf '%0250d' "$i")"; done
    mkdir manydirs; (cd manydirs && jot $((300 * scale)) | xargs mkdir)
    p=deep; for i in $(jot $((scale == 1 ? 40 : 90))); do p=$p/level$i; done; mkdir -p "$p"; echo bottom > "$p/file"
    # Sizes around fragments, blocks and the end of the direct blocks.
    for n in 0 1 $((inl - 1)) $inl $((inl + 1)) 511 512 513 $((fs - 1)) $fs $((fs + 1)) \
        $((bs - fs)) $((bs - 1)) $bs $((bs + 1)) $((bs + fs + 1)) $((3 * bs + 2 * fs + 17)) \
        $((12 * bs - 1)) $((12 * bs)) $((12 * bs + 1)) $((12 * bs + fs + 3)); do
        gen "$n" "size $n" > "big/size$n"
    done
    # One byte at the first indirect, double-indirect and triple-indirect block, and holes.
    printf start > big/ind1; printf one | dd of=big/ind1 bs=1 seek=$((12 * bs)) conv=notrunc status=none
    printf start > big/ind2; printf two | dd of=big/ind2 bs=1 seek=$(((12 + nindir) * bs + 5)) conv=notrunc status=none
    printf start > big/ind3
    printf three | dd of=big/ind3 bs=1 seek=$(((12 + nindir + nindir * nindir) * bs + 7)) conv=notrunc status=none
    printf start > big/sparse; printf middle | dd of=big/sparse bs=1 seek=$((5 * bs + 100)) conv=notrunc status=none
    printf end | dd of=big/sparse bs=1 seek=$((40 * bs)) conv=notrunc status=none
    for i in $(jot 30 0); do gen "$fs" "hole $i" | dd of=frag/holes bs="$fs" seek=$((i * 3 * bs / fs)) conv=notrunc status=none; done
    # Fragmented: interleaved writes of two files, then one removed.
    for i in $(jot 40); do gen "$bs" "a $i" >> frag/a; gen "$bs" "b $i" >> frag/b; sync; done
    rm frag/b; gen $((10 * bs + 123)) after > frag/after
    # Links: hard links, symlinks around the inline limit, long, relative and dangling ones.
    echo target > links/target; ln links/target links/hard1; ln links/target links/hard2
    ln -s target links/short
    for n in $((inl - 1)) $inl $((inl + 1)) 200; do ln -s "$(printf "%0${n}d" 0)" "links/len$n"; done
    ln -s "/$(jot -b dddddddd/ -s '' 110)" links/len990
    ln -s ../etc/passwd links/relative; ln -s /nonexistent links/dangling
    # Special files and modes.
    mkfifo special/fifo; mknod special/char c 1 3 2>/dev/null || true; mknod special/block b 7 0 2>/dev/null || true
    echo x > special/setuid; chmod 4755 special/setuid
    mkdir special/sticky; chmod 1777 special/sticky
    echo x > special/none; chmod 0000 special/none
    # Names.
    echo x > "odd/with space"; echo x > 'odd/quote"double'; echo x > "odd/naïve-ünïcödé-日本語"
    echo x > 'odd/back\slash'; echo x > 'odd/-leading-dash'; echo x > 'odd/trailing.'
    echo x > 'odd/semi;colon|pipe'; echo x > "$(printf 'odd/bad\377name')"
    # Owners and times (UFS1 keeps 32-bit seconds: 2040 and 2200 wrap as the kernel stores them).
    echo x > owners/big; chown 4000000000:4000000001 owners/big
    echo x > owners/nobody; chown 65534:65534 owners/nobody
    echo x > times/y1960; touch -d 1960-01-02T03:04:05Z times/y1960
    echo x > times/y2040; touch -d 2040-01-02T03:04:05Z times/y2040
    echo x > times/y2200; touch -d 2200-01-02T03:04:05Z times/y2200
    echo x > times/nanos; touch -d 2024-03-10T01:02:03.123456789Z times/nanos
    # A deleted file and a renamed directory: stale entries in the directory blocks.
    echo gone > etc/deleted; rm etc/deleted; mkdir etc/old; echo x > etc/old/f; mv etc/old etc/new
    cd /
}

truth() { # truth NAME DIR
    (cd "$2" && find . -mindepth 1 -print0 | sort -z |
        xargs -0 stat -f '%N	%Xp	%i	%l	%z	%u	%g	%.9Fa	%.9Fm	%.9Fc	%.9FB	%Y' | sed 's#^\./##') |
        zstd -19 -q -f -o "$out/$1.truth.zst"
    (cd "$2" && find . -type f -size +0 -size -300M -print0 | sort -z | xargs -0 sha256sum | sed 's#  \./#  #') > "$out/$1.sha256"
}

finish() { # finish NAME IMAGE
    # label_disk NAME SCHEME [gpart add arguments; ...]: a 64 MiB disk partitioned by gpart, a
# small UFS in each freebsd-ufs partition holding one file that names the partition.
label_disk() {
    name=$1 scheme=$2; shift 2
    img=$w/$name.img; rm -f "$img"; truncate -s 64m "$img"
    md=$(mdconfig -a -t vnode -f "$img")
    gpart create -s "$scheme" "$md" > /dev/null
    for spec in "$@"; do
        # "SUB:ARGS" partitions inside partition SUB (a bsdlabel in an MBR slice).
        case "$spec" in
            *:*) geom=$md${spec%%:*}; args=${spec#*:}
                gpart show "$geom" > /dev/null 2>&1 || gpart create -s bsd "$geom" > /dev/null ;;
            *) geom=$md; args=$spec ;;
        esac
        gpart add $args "$geom" > /dev/null
    done
    for dev in $({ gpart show -p "$md"; gpart show -p "${md}s1" 2>/dev/null || true; } | awk '$4 == "freebsd-ufs" {print $3}'); do
        newfs -U "/dev/$dev" > /dev/null
        mkdir -p /l; mount "/dev/$dev" /l; echo "partition $dev" > /l/marker; umount /l
    done
    { gpart show -p "$md"; gpart show -p "${md}s1" 2>/dev/null || true; } > "$out/$name.gpart"
    mdconfig -d -u "$md"
    zstd -19 -q -f --rm "$img" -o "$out/$name.img.zst"
}

if [ "$mode" = labels ]; then
    label_disk mbr-bsdlabel mbr "-t freebsd -s 48m" "s1:-t freebsd-ufs -s 16m" "s1:-t freebsd-swap -s 8m" \
        "s1:-t freebsd-ufs -s 16m" "-t freebsd -s 8m"
    label_disk gpt-freebsd gpt "-t freebsd-boot -s 512k" "-t freebsd-ufs -s 20m" "-t freebsd-swap -s 8m" \
        "-t freebsd-ufs"
    exit 0
fi

if [ "$mode" = matrix ]; then mv "$2" "$out/$1.img"; else zstd -19 -q -f --rm "$2" -o "$out/$1.img.zst"; fi
}

# newfs_image NAME MIB VERSION BSIZE FSIZE [newfs options]
newfs_image() {
    name=$1 mib=$2 v=$3 bs=$4 fs=$5; shift 5
    [ -f "$out/$name.img" ] && return
    img=$w/$name.img; rm -f "$img"; truncate -s "${mib}m" "$img"
    md=$(mdconfig -a -t vnode -f "$img")
    newfs -O "$v" -b "$bs" -f "$fs" "$@" "/dev/$md" > /dev/null
    mount -o noatime "/dev/$md" /m
    fill /m "$v" "$bs" "$fs" "$scale"
    sync
    truth "$name" /m
    umount /m
    fsck_ffs -fn "/dev/$md" > "$w/$name.fsck" 2>&1 || { cat "$w/$name.fsck"; exit 1; }
    dumpfs -m "/dev/$md"
    mdconfig -d -u "$md"
    finish "$name" "$img"
}

# makefs_pair NAME MIB VERSION BSIZE FSIZE: NAME-le and NAME-be from one tree.
makefs_pair() {
    name=$1 mib=$2 v=$3 bs=$4 fs=$5
    src=$w/src.img; rm -f "$src"; truncate -s "$((mib * 2))m" "$src"
    smd=$(mdconfig -a -t vnode -f "$src"); newfs -O2 -i 4096 "/dev/$smd" > /dev/null; mount -o noatime "/dev/$smd" /src
    fill /src "$v" "$bs" "$fs" "$scale"
    # makefs copies files in full: the sparse files would not fit, so they go.
    rm /src/big/ind2 /src/big/ind3
    for e in le be; do
        rm -f "$w/$name-$e.img"
        makefs -t ffs -B "$e" -s "${mib}m" -o "version=$v,bsize=$bs,fsize=$fs" "$w/$name-$e.img" /src > /dev/null
    done
    umount /src; mdconfig -d -u "$smd"; rm -f "$src"
    md=$(mdconfig -a -t vnode -f "$w/$name-le.img"); mount -o ro "/dev/$md" /m
    truth "$name-le" /m
    umount /m; fsck_ffs -fn "/dev/$md" > /dev/null; mdconfig -d -u "$md"
    cp "$out/$name-le.truth.zst" "$out/$name-be.truth.zst"; cp "$out/$name-le.sha256" "$out/$name-be.sha256"
    finish "$name-le" "$w/$name-le.img"; finish "$name-be" "$w/$name-be.img"
}

# dirty_image NAME MIB: SU+J, copied while mounted (no unmount before the copy). Its truth is
# a read-only mount of the copy (the journal is not replayed): what is on disk, which lags
# what the live mount showed by the last seconds of changes.
dirty_image() {
    name=$1 mib=$2
    img=$w/$name.img; rm -f "$img"; truncate -s "${mib}m" "$img"
    md=$(mdconfig -a -t vnode -f "$img")
    newfs -O2 -U -j -i 4096 "/dev/$md" > /dev/null
    mount -o noatime "/dev/$md" /m
    fill /m 2 32768 4096 "$scale"
    sync; sleep 2
    dd if="/dev/$md" of="$w/$name.copy" bs=1m status=none
    umount /m; mdconfig -d -u "$md"; rm -f "$img"
    cp "$w/$name.copy" "$img"
    md=$(mdconfig -a -t vnode -f "$img")
    mount -r "/dev/$md" /m
    truth "$name" /m
    umount /m; mdconfig -d -u "$md"; rm -f "$img"
    finish "$name" "$w/$name.copy"
}

# label_disk NAME SCHEME [gpart add arguments; ...]: a 64 MiB disk partitioned by gpart, a
# small UFS in each freebsd-ufs partition holding one file that names the partition.
label_disk() {
    name=$1 scheme=$2; shift 2
    img=$w/$name.img; rm -f "$img"; truncate -s 64m "$img"
    md=$(mdconfig -a -t vnode -f "$img")
    gpart create -s "$scheme" "$md" > /dev/null
    for spec in "$@"; do
        # "SUB:ARGS" partitions inside partition SUB (a bsdlabel in an MBR slice).
        case "$spec" in
            *:*) geom=$md${spec%%:*}; args=${spec#*:}
                gpart show "$geom" > /dev/null 2>&1 || gpart create -s bsd "$geom" > /dev/null ;;
            *) geom=$md; args=$spec ;;
        esac
        gpart add $args "$geom" > /dev/null
    done
    for dev in $({ gpart show -p "$md"; gpart show -p "${md}s1" 2>/dev/null || true; } | awk '$4 == "freebsd-ufs" {print $3}'); do
        newfs -U "/dev/$dev" > /dev/null
        mkdir -p /l; mount "/dev/$dev" /l; echo "partition $dev" > /l/marker; umount /l
    done
    { gpart show -p "$md"; gpart show -p "${md}s1" 2>/dev/null || true; } > "$out/$name.gpart"
    mdconfig -d -u "$md"
    zstd -19 -q -f --rm "$img" -o "$out/$name.img.zst"
}

if [ "$mode" = labels ]; then
    label_disk mbr-bsdlabel mbr "-t freebsd -s 48m" "s1:-t freebsd-ufs -s 16m" "s1:-t freebsd-swap -s 8m" \
        "s1:-t freebsd-ufs -s 16m" "-t freebsd -s 8m"
    label_disk gpt-freebsd gpt "-t freebsd-boot -s 512k" "-t freebsd-ufs -s 20m" "-t freebsd-swap -s 8m" \
        "-t freebsd-ufs"
    exit 0
fi

if [ "$mode" = matrix ]; then
    scale=${MATRIX_SCALE:-4}; m=${MATRIX_MIB:-256}
    newfs_image m-ufs2-default "$m" 2 32768 4096
    newfs_image m-ufs2-su "$m" 2 32768 4096 -U
    newfs_image m-ufs2-suj "$m" 2 32768 4096 -U -j
    newfs_image m-ufs2-4k "$m" 2 4096 512
    newfs_image m-ufs2-8k "$m" 2 8192 1024 -U
    newfs_image m-ufs2-16k "$m" 2 16384 2048
    newfs_image m-ufs2-64k "$m" 2 65536 8192 -U
    newfs_image m-ufs2-64k-full 1024 2 65536 65536 -i 65536
    newfs_image m-ufs2-dense "$m" 2 32768 4096 -i 1024
    newfs_image m-ufs1-default "$m" 1 32768 4096
    newfs_image m-ufs1-8k "$m" 1 8192 1024 -U
    newfs_image m-ufs1-4k "$m" 1 4096 512
    makefs_pair m-mk2 "$m" 2 32768 4096
    makefs_pair m-mk1 "$m" 1 8192 1024
    dirty_image m-dirty "$m"
    exit 0
fi

scale=1
if [ "$mode" = dirty ]; then dirty_image dirty 40; exit 0; fi
newfs_image ufs2 16 2 32768 4096 -U -i 4096
newfs_image ufs2-4k 16 2 4096 512 -i 2048
newfs_image ufs2-64k 32 2 65536 8192 -i 8192
newfs_image ufs1 16 1 8192 1024 -i 2048
newfs_image ufs2-suj 40 2 32768 4096 -U -j -i 4096
makefs_pair mk2 32 2 32768 4096
makefs_pair mk1 32 1 8192 1024
dirty_image dirty 40
