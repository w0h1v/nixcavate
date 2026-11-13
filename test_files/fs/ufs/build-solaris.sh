#!/bin/bash
# Builds the Solaris UFS test images and their ground truth with illumos's own tools. Run as
# root in a throwaway OmniOS (illumos) VM; the images here came from the r151060 cloud image:
#
#   bash build-solaris.sh OUTDIR
#
# Each image: mkfile, lofiadm, newfs, mount with noatime (UFS logging on unless the name says
# nologging),
# the tree below, listed with GNU stat/readlink/sha256sum while mounted, unmounted, checked with
# fsck. `sol-dirty` is copied while mounted (its log not rolled) and listed from that mount.
# Outputs per image NAME: NAME.img.zst, NAME.truth.zst (the fields of build.sh; UFS on illumos
# has no birth time, so that field is 0) and NAME.sha256.
set -eu
export LC_ALL=C PATH=/usr/gnu/bin:/usr/bin:/usr/sbin
out=$(cd "${1:?output dir}" && pwd)
w=/var/tmp/solbuild
mkdir -p $w /sm
[ -f $w/seq ] || seq 1 1000000 > $w/seq
gen() { [ "$1" -eq 0 ] || (echo "$2"; cat $w/seq $w/seq) | head -c "$1"; }

fill() { # fill DIR: the tree of build.sh for 8 KiB blocks and 1 KiB fragments, UFS1 limits
    cd "$1"
    bs=8192 fs=1024 nindir=2048 inl=56
    mkdir -p etc var/log big deep odd links special times owners frag
    printf 'root:x:0:0:Super-User:/root:/usr/bin/bash\n' > etc/passwd
    echo solhost > etc/nodename
    mkdir manyfiles; (cd manyfiles && seq -f 'f%g' 1 2500 | xargs touch)
    mkdir longnames; for i in $(seq 1 40); do echo "$i" > "longnames/$(printf '%0250d' "$i")"; done
    mkdir manydirs; (cd manydirs && seq 1 300 | xargs mkdir)
    p=deep; for i in $(seq 1 40); do p=$p/level$i; done; mkdir -p "$p"; echo bottom > "$p/file"
    for n in 0 1 $((inl - 1)) $inl $((inl + 1)) 59 60 61 511 512 513 $((fs - 1)) $fs $((fs + 1)) \
        $((bs - fs)) $((bs - 1)) $bs $((bs + 1)) $((bs + fs + 1)) $((3 * bs + 2 * fs + 17)) \
        $((12 * bs - 1)) $((12 * bs)) $((12 * bs + 1)) $((12 * bs + fs + 3)); do
        gen "$n" "size $n" > "big/size$n"
    done
    printf start > big/ind1; printf one | dd of=big/ind1 bs=1 seek=$((12 * bs)) conv=notrunc status=none
    printf start > big/ind2; printf two | dd of=big/ind2 bs=1 seek=$(((12 + nindir) * bs + 5)) conv=notrunc status=none
    printf start > big/ind3
    printf three | dd of=big/ind3 bs=1 seek=$(((12 + nindir + nindir * nindir) * bs + 7)) conv=notrunc status=none
    printf start > big/sparse; printf middle | dd of=big/sparse bs=1 seek=$((5 * bs + 100)) conv=notrunc status=none
    printf end | dd of=big/sparse bs=1 seek=$((40 * bs)) conv=notrunc status=none
    for i in $(seq 0 29); do gen "$fs" "hole $i" | dd of=frag/holes bs="$fs" seek=$((i * 3 * bs / fs)) conv=notrunc status=none; done
    for i in $(seq 1 40); do gen "$bs" "a $i" >> frag/a; gen "$bs" "b $i" >> frag/b; sync; done
    rm frag/b; gen $((10 * bs + 123)) after > frag/after
    echo target > links/target; ln links/target links/hard1; ln links/target links/hard2
    ln -s target links/short
    for n in 55 56 57 59 60 61 200; do ln -s "$(printf "%0${n}d" 0)" "links/len$n"; done
    ln -s "/$(printf 'dddddddd/%.0s' $(seq 1 110))" links/len990
    ln -s ../etc/passwd links/relative; ln -s /nonexistent links/dangling
    mkfifo special/fifo; mknod special/char c 13 2; mknod special/block b 7 0
    echo x > special/setuid; chmod 4755 special/setuid
    mkdir special/sticky; chmod 1777 special/sticky
    echo x > special/none; chmod 0000 special/none
    echo x > "odd/with space"; echo x > 'odd/quote"double'; echo x > "odd/naïve-ünïcödé-日本語"
    echo x > 'odd/back\slash'; echo x > 'odd/-leading-dash'; echo x > 'odd/trailing.'
    echo x > 'odd/semi;colon|pipe'; echo x > "$(printf 'odd/bad\377name')"
    echo x > owners/big; chown 2147483646:2147483645 owners/big
    echo x > owners/mid; chown 70000:80000 owners/mid
    echo x > owners/nobody; chown 60001:60001 owners/nobody
    echo x > times/y1960; touch -d '1960-01-02 03:04:05 UTC' times/y1960
    echo x > times/nanos; touch -d '2024-03-10 01:02:03.123456789 UTC' times/nanos
    echo gone > etc/deleted; rm etc/deleted; mkdir etc/old; echo x > etc/old/f; mv etc/old etc/new
    cd /
}

truth() { # truth NAME DIR
    (cd "$2" && find . -mindepth 1 -print0 | sort -z | while IFS= read -r -d '' p; do
        printf '%s\t%s\t%s\n' "${p#./}" \
            "$(stat -c '%f	%i	%h	%s	%u	%g	%.9X	%.9Y	%.9Z	0' "$p")" "$(readlink "$p" || true)"
    done) | zstd -19 -q -f -o "$out/$1.truth.zst"
    (cd "$2" && find . -type f -size +0 -size -300M -print0 | sort -z | xargs -0 sha256sum | sed 's#  \./#  #') > "$out/$1.sha256"
}

image() { # image NAME MIB [mount options]
    name=$1 mib=$2 opts=noatime${3:+,$3}
    img=$w/$name.img; rm -f "$img"; mkfile "${mib}m" "$img"
    dev=$(lofiadm -a "$img"); rdev=$(echo "$dev" | sed 's#/lofi/#/rlofi/#')
    echo y | newfs -i 2048 "$rdev" > /dev/null 2>&1
    mount -F ufs -o "$opts" "$dev" /sm
    fill /sm
    sync
    if [ "$name" = sol-dirty ]; then
        lockfs -w /sm; dd if="$rdev" of="$w/$name.copy" bs=1024k 2>/dev/null; lockfs -u /sm
        truth "$name" /sm
        umount /sm; lofiadm -d "$dev"; rm -f "$img"; mv "$w/$name.copy" "$img"
    else
        truth "$name" /sm
        umount /sm
        fsck -F ufs -n "$rdev" > /dev/null
        lofiadm -d "$dev"
    fi
    zstd -19 -q -f --rm "$img" -o "$out/$name.img.zst"
}

image sol-ufs 24
image sol-nologging 24 nologging
image sol-dirty 24
