#!/usr/bin/bash
# phase 3 (after the collections): lastlog banners, SMF reference dumps from the repository's own sqlite shell
export HOME=/root PATH=/usr/bin:/usr/sbin:/sbin:/opt/ooce/bin:/usr/gnu/bin
T=/root/nxtruth3; mkdir -p $T; SSHO="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
# lastlog: a copy of the file, then an interactive login per user, whose banner is read from the same file
cp -p /var/adm/lastlog.v2 $T/lastlog.v2.before-banner; cp -p /etc/passwd $T/passwd.before-banner
for u in alice omnios; do
  echo "== $u" >> $T/ssh-banners.txt
  printf 'exit\n' | ssh -tt -i /root/.ssh/nx_alice_id -o IdentitiesOnly=yes $SSHO $u@127.0.0.1 >> $T/ssh-banners.txt 2>&1
done
# omnios has no key of root's: use a password-less path via su from root instead (the banner is printed by sshd only)
cp -p /var/adm/lastlog.v2 $T/lastlog.v2.after-banner
# SMF: counts and full table dumps from the repository's own SQLite 2 shell, on a copy
cp /etc/svc/repository.db $T/repository.db.copy
Q="/lib/svc/bin/sqlite $T/repository.db.copy"
for t in service_tbl instance_tbl snapshot_lnk_tbl snaplevel_tbl snaplevel_lnk_tbl pg_tbl prop_lnk_tbl value_tbl id_tbl schema_version; do
  echo "$t	$($Q "select count(*) from $t")" >> $T/sqlite-counts.tsv
  $Q "select * from $t" > $T/sqlite-dump.$t.txt 2>&1
done
$Q '.schema' > $T/sqlite-schema.txt 2>&1
# per instance: enabled and methods as svcprop prints them
for f in $(svcs -a -H -o fmri); do
  printf '%s\t%s\t%s\t%s\t%s\n' "$f" "$(svcprop -p general/enabled $f 2>&1)" "$(svcprop -p start/exec $f 2>&1)" "$(svcprop -p stop/exec $f 2>&1)" "$(svcprop -p refresh/exec $f 2>&1)"
done > $T/smf-native.tsv
svcs -a -H -o fmri,state > $T/smf-states.tsv
# a small repository made by the real svccfg from one manifest (a fixture-sized SQLite 2.1 file)
rm -f $T/small.db; SVCCFG_REPOSITORY=$T/small.db svccfg import /var/svc/manifest/site/nxmk-smf.xml > $T/small-import.txt 2>&1
SVCCFG_REPOSITORY=$T/small.db svccfg import /lib/svc/manifest/site/nxmk-smf-lib.xml >> $T/small-import.txt 2>&1
ls -la $T/small.db > $T/small-ls.txt 2>&1; /lib/svc/bin/sqlite $T/small.db '.schema' | head -3 >> $T/small-ls.txt
SVCCFG_REPOSITORY=$T/small.db svccfg list > $T/small-list.txt 2>&1
for f in $(SVCCFG_REPOSITORY=$T/small.db svccfg list); do :; done
/lib/svc/bin/sqlite $T/small.db "select count(*) from service_tbl; select count(*) from prop_lnk_tbl;" >> $T/small-ls.txt 2>&1
for t in service_tbl instance_tbl pg_tbl prop_lnk_tbl value_tbl snapshot_lnk_tbl snaplevel_tbl snaplevel_lnk_tbl; do /lib/svc/bin/sqlite $T/small.db "select * from $t" > $T/small-dump.$t.txt 2>&1; done
du -sh /kernel/drv /kernel/drv/amd64 > $T/du-kernel-drv.txt 2>&1
ls /kernel/drv/*.conf | wc -l >> $T/du-kernel-drv.txt
cd / && tar cf /root/nxtar-kerneldrv.tar kernel/drv 2>/dev/null
cd /root && tar cf /root/nxtruth3.tar nxtruth3
echo PHASE3_DONE
