#!/usr/bin/bash
# nixcavate illumos harness (OmniOS). Run as root: nxsol.sh phase1 | phase2. Example data only:
# users alice/mallory/bob, example passwords, keys generated here. Steps are logged to /root/nxtruth/run.log.
export HOME=/root PATH=/usr/bin:/usr/sbin:/sbin:/opt/ooce/bin:/usr/gnu/bin
NXDIR=/root/nx; TRUTH=/root/nxtruth; GT=$TRUTH/ground-truth.tsv; PTY="python3 /var/tmp/nxptyrun.py"
PHASE=${1:-phase1}
mkdir -p $NXDIR $TRUTH
exec >> $TRUTH/run.log 2>&1
gt() { k=$1; shift; printf '%s\t%s\n' "$k" "$*" >> $GT; }
step() { printf '\n=== [%s] %s\n' "$PHASE" "$*"; }
now() { date +%s; }
plant() { gt plant "$1	$2	$3"; }
SSHO="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

phase1() {
  : > $GT
  gt tag "$(cat $NXDIR/tag)"; gt release "$(head -2 /etc/release | tr '\n' ' ')"; gt kernel "$(uname -v)"; gt arch "$(uname -p)"
  gt hostname "$(hostname)"; gt zonename "$(zonename)"; gt start_epoch "$(now)"
  gt n_ok_logins_alice 5; gt m_failed_mallory 4; gt m_failed_ghost 3; gt k_sudo 4; gt k_su 2
  gt wtmpx_size_at_start "$(stat -c %s /var/adm/wtmpx 2>/dev/null || ls -l /var/adm/wtmpx | awk '{print $5}')"

  step "infrastructure packages (fwtmp, svr4 tools, headers)"
  for p in system/accounting/legacy package/svr4 system/header security/sudo; do
    pkg install $p >/dev/null 2>&1; rc=$?; [ $rc -eq 0 -o $rc -eq 4 ] && gt infra_ok $p || gt infra_missing "$p rc=$rc"
  done
  # OmniOS sends no auth.* messages anywhere by default; add the usual authlog rule (harness change, noted in the README)
  printf 'auth.info\t\t\t\t\t\t/var/log/authlog\n' > /etc/rsyslog.d/nx-auth.conf
  svcadm restart system-log:rsyslog; sleep 3
  gt harness_note "added /etc/rsyslog.d/nx-auth.conf: auth.info -> /var/log/authlog (OmniOS default logs no auth messages)"
  touch /var/adm/sulog /var/adm/loginlog; chmod 600 /var/adm/loginlog; chown root:sys /var/adm/loginlog /var/adm/sulog
  gt harness_note "created empty /var/adm/sulog and /var/adm/loginlog (the logs are only written when the file exists)"

  step "auditing (BSM)"
  auditconfig -setpolicy +argv,+arge 2>&1
  auditconfig -setflags lo,ex,ad,ps,as 2>&1
  auditconfig -setnaflags lo 2>&1
  svcadm enable -s auditd; sleep 2; audit -s
  { auditconfig -getflags; auditconfig -getnaflags; auditconfig -getpolicy; auditconfig -getplugin audit_binfile; svcs -l auditd; } > $TRUTH/auditconfig.txt 2>&1
  gt audit_flags "$(auditconfig -getflags | tr '\n' ' ')"; gt audit_policy "$(auditconfig -getpolicy | tr '\n' ' ')"
  gt audit_start_epoch "$(now)"

  step "users and roles"
  mkdir -p /root/.ssh; chmod 700 /root/.ssh
  ssh-keygen -q -t ed25519 -N '' -C alice-nx-key -f /root/.ssh/nx_alice_id
  gt users_start_epoch "$(now)"
  useradd -m -d /home/alice -s /usr/bin/bash -c 'Alice Example' alice; useradd -m -d /home/mallory -s /usr/bin/bash -c 'Mallory Example' mallory
  $PTY -p 'Nx-Alice-Example-1' -p 'Nx-Alice-Example-1' -- passwd alice > $TRUTH/passwd-alice.txt
  $PTY -p 'Nx-Mallory-Unused-1' -p 'Nx-Mallory-Unused-1' -- passwd mallory > $TRUTH/passwd-mallory.txt
  $PTY -p 'Nx-Root-Example-1' -p 'Nx-Root-Example-1' -- passwd root > $TRUTH/passwd-root.txt
  roleadd -m -d /home/svcrole -s /usr/bin/pfbash -P 'Service Management' -c 'Service role' svcrole
  $PTY -p 'Nx-Role-Example-1' -p 'Nx-Role-Example-1' -- passwd svcrole > $TRUTH/passwd-svcrole.txt
  usermod -R svcrole alice
  mkdir -p /home/alice/.ssh; cp /root/.ssh/nx_alice_id.pub /home/alice/.ssh/authorized_keys
  chown -R alice:other /home/alice/.ssh; chmod 700 /home/alice/.ssh; chmod 600 /home/alice/.ssh/authorized_keys
  gt users_created "alice,mallory,svcrole(role)"; gt users_end_epoch "$(now)"
  # sshd: password auth on (default already yes), restart; ssh listens on the console-forwarded port 22
  grep -q '^PerSourcePenalties' /etc/ssh/sshd_config || printf 'PerSourcePenalties no\n' >> /etc/ssh/sshd_config
  grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || printf 'PasswordAuthentication yes\nPubkeyAuthentication yes\n' >> /etc/ssh/sshd_config
  svcadm restart ssh; sleep 3
  printf 'Defaults:alice !requiretty\n# NXMK_SUDOERS\nalice ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/90-nx-alice; chmod 440 /etc/sudoers.d/90-nx-alice
  visudo -c >/dev/null 2>&1 && gt sudoers_dropin valid || gt sudoers_dropin INVALID

  step "ssh logins (5 ok as alice, 4 failed mallory, 3 failed ghostuser)"
  gt logins_start_epoch "$(now)"
  ok=0; i=1
  while [ $i -le 5 ]; do
    ssh -tt -i /root/.ssh/nx_alice_id -o IdentitiesOnly=yes -o BatchMode=yes -o PasswordAuthentication=no $SSHO alice@127.0.0.1 '/usr/bin/id' </dev/null >/dev/null 2>&1 && ok=$((ok+1))
    sleep 1; i=$((i+1)); done
  gt observed_ssh_ok "$ok"
  fm=0; i=1; while [ $i -le 4 ]; do $PTY -p 'Wrong-Password-Example' -- ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 $SSHO mallory@127.0.0.1 true >/dev/null 2>&1 || fm=$((fm+1)); sleep 1; i=$((i+1)); done
  fg=0; i=1; while [ $i -le 3 ]; do $PTY -p 'Wrong-Password-Example' -- ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 $SSHO ghostuser@127.0.0.1 true >/dev/null 2>&1 || fg=$((fg+1)); sleep 1; i=$((i+1)); done
  gt observed_fail_nonzero_mallory "$fm"; gt observed_fail_nonzero_ghost "$fg"; gt logins_end_epoch "$(now)"

  step "console-style failed logins (login(1): loginlog after 5 failures)"
  gt loginfail_start_epoch "$(now)"
  $PTY -p bad1 -p bad2 -p bad3 -p bad4 -p bad5 -l mallory -- login mallory > $TRUTH/login-fail.txt 2>&1
  gt loginfail_end_epoch "$(now)"

  step "sudo x4, su x2 (+1 failed su), pfexec, role su"
  gt sudo_start_epoch "$(now)"; sc=0
  for c in "/usr/bin/id" "/usr/bin/ls /root" "/usr/bin/whoami" "/usr/bin/cat /etc/nodename"; do
    su alice -c "sudo -n $c" >/dev/null 2>&1 && sc=$((sc+1)); gt sudo_command "$c"; sleep 1; done
  gt observed_sudo_ok "$sc"
  gt su_start_epoch "$(now)"
  su - alice -c 'id -un' >/dev/null 2>&1; su - alice -c 'pwd' >/dev/null 2>&1   # root to alice: no password
  su alice -c "$PTY -p 'Nx-Root-Example-1' -- su root -c id" > $TRUTH/su-alice-root-ok.txt 2>&1
  su alice -c "$PTY -p 'Wrong-Root-Password' -- su root -c id" > $TRUTH/su-alice-root-bad.txt 2>&1
  su alice -c "$PTY -p 'Nx-Role-Example-1' -- su svcrole -c 'pfexec /usr/sbin/svcs -H -o fmri svc:/system/cron:default'" > $TRUTH/su-role.txt 2>&1
  gt su_end_epoch "$(now)"
  gt pfexec_start_epoch "$(now)"
  su alice -c 'pfexec id' > $TRUTH/pfexec-alice.txt 2>&1   # alice has no profile: refused/unprivileged
  su omnios -c 'pfexec id' > $TRUTH/pfexec-omnios.txt 2>&1 </dev/null
  gt pfexec_end_epoch "$(now)"

  step "account changes for bob + groupadd"
  gt acct_start_epoch "$(now)"
  groupadd nxgroup
  useradd -m -d /home/bob -s /usr/bin/bash bob
  $PTY -p 'Nx-Bob-Example-1' -p 'Nx-Bob-Example-1' -- passwd bob > /dev/null 2>&1
  usermod -G nxgroup bob
  passwd -l bob >/dev/null 2>&1
  userdel -r bob 2>&1
  gt acct_ops "groupadd nxgroup; useradd bob; passwd bob; usermod -G nxgroup bob; passwd -l bob; userdel -r bob"
  gt acct_end_epoch "$(now)"
  for i in 1 2 3 4; do /usr/bin/id >/dev/null; done; gt root_exec_id_direct 4

  step "packages: install 3, remove 1"
  gt pkg_events_start_epoch "$(now)"
  pkg install ooce/file/tree ooce/util/jq ooce/file/lsof > $TRUTH/pkg-install.log 2>&1 && gt pkgs_installed "tree,jq,lsof" || gt pkgs_installed FAILED
  sleep 1
  pkg uninstall ooce/file/lsof > $TRUTH/pkg-remove.log 2>&1 && gt pkgs_removed lsof || gt pkgs_removed FAILED
  gt pkg_events_end_epoch "$(now)"

  step "SVR4 package (real pkgmk/pkgadd from package/svr4)"
  gt svr4_start_epoch "$(now)"
  mkdir -p /tmp/nxpkg/root/opt/nxsvr4 /tmp/nxpkg/spool; echo 'example SVR4 payload' > /tmp/nxpkg/root/opt/nxsvr4/readme
  printf 'i pkginfo\nd none /opt/nxsvr4 0755 root bin\nf none /opt/nxsvr4/readme 0644 root bin\n' > /tmp/nxpkg/prototype
  printf 'PKG=NXexample\nNAME=Example SVR4 package\nVERSION=1.0\nARCH=i386\nCATEGORY=application\nVENDOR=Example\nBASEDIR=/\nCLASSES=none\n' > /tmp/nxpkg/pkginfo
  (cd /tmp/nxpkg && pkgmk -o -r /tmp/nxpkg/root -d /tmp/nxpkg/spool -f prototype NXexample > $TRUTH/svr4-pkgmk.txt 2>&1 && yes | pkgadd -n -d /tmp/nxpkg/spool NXexample > $TRUTH/svr4-pkgadd.txt 2>&1 </dev/null) ; gt svr4_rc "$?"
  gt svr4_end_epoch "$(now)"

  step "cron and at"
  gt cron_start_epoch "$(now)"
  printf '* * * * * /usr/bin/true #nxcron-every-minute\n' | su alice -c crontab 2>&1 || gt plant_failed NXCRON
  echo '* * * * * /usr/bin/id >/dev/null 2>&1' > /tmp/nx-rootcron; (crontab -l 2>/dev/null; cat /tmp/nx-rootcron) | crontab
  plant NXMK_USERCRON "crontab alice" cron
  # a failing job so the cron log shows rc=1 lines
  (crontab -l; echo '* * * * * /usr/bin/false #nxfalse') | crontab
  gt cron_end_epoch "$(now)"
  echo '/tmp/.NXMK_AT/agent --quiet' | at now + 3 days 2>&1 | tee $TRUTH/at-submit.txt; plant NXMK_AT "at job (atq)" at

  step "persistence plants"
  mkdir -p /tmp/nxplant; gt plants_start_epoch "$(now)"
  (crontab -l | grep -v 'usr/bin/id' | grep -v nxfalse; echo '*/5 * * * * /tmp/.NXMK_CRON/agent --quiet') > /tmp/nx-rc2; crontab /tmp/nx-rc2; plant NXMK_CRON "crontab root" cron
  # SMF: site manifest, method script, import and enable
  mkdir -p /var/svc/manifest/site /var/svc/method /lib/svc/manifest/site
  printf '#!/sbin/sh\n# NXMK_SMF\n/tmp/.NXMK_SMF/agent >/dev/null 2>&1 &\nexit 0\n' > /var/svc/method/nxmk-smf; chmod 755 /var/svc/method/nxmk-smf
  cat > /var/svc/manifest/site/nxmk-smf.xml <<'X'
<?xml version="1.0"?>
<!DOCTYPE service_bundle SYSTEM "/usr/share/lib/xml/dtd/service_bundle.dtd.1">
<!-- NXMK_SMF example service -->
<service_bundle type="manifest" name="nxmk-smf">
  <service name="site/nxmk-smf" type="service" version="1">
    <create_default_instance enabled="false"/>
    <single_instance/>
    <dependency name="fs" grouping="require_all" restart_on="none" type="service"><service_fmri value="svc:/system/filesystem/local"/></dependency>
    <exec_method type="method" name="start" exec="/var/svc/method/nxmk-smf %m" timeout_seconds="60"/>
    <exec_method type="method" name="stop" exec=":true" timeout_seconds="60"/>
    <property_group name="startd" type="framework"><propval name="duration" type="astring" value="transient"/></property_group>
    <stability value="Unstable"/>
    <template><common_name><loctext xml:lang="C">NXMK_SMF example</loctext></common_name></template>
  </service>
</service_bundle>
X
  svccfg import /var/svc/manifest/site/nxmk-smf.xml 2>&1; svcadm enable -s svc:/site/nxmk-smf:default 2>&1; plant NXMK_SMF /var/svc/manifest/site/nxmk-smf.xml smf
  # second service in lib/svc/manifest/site, disabled, with a suspicious method
  cat > /lib/svc/manifest/site/nxmk-smf-lib.xml <<'X'
<?xml version="1.0"?>
<!DOCTYPE service_bundle SYSTEM "/usr/share/lib/xml/dtd/service_bundle.dtd.1">
<service_bundle type="manifest" name="nxmk-smf-lib">
  <service name="site/nxmk-smf-lib" type="service" version="1">
    <create_default_instance enabled="true"/>
    <single_instance/>
    <exec_method type="method" name="start" exec="/tmp/.NXMK_SMFLIB/agent --quiet" timeout_seconds="10"/>
    <exec_method type="method" name="stop" exec=":kill" timeout_seconds="10"/>
    <property_group name="startd" type="framework"><propval name="duration" type="astring" value="child"/></property_group>
    <stability value="Unstable"/>
    <template><common_name><loctext xml:lang="C">NXMK_SMFLIB example</loctext></common_name></template>
  </service>
</service_bundle>
X
  svccfg import /lib/svc/manifest/site/nxmk-smf-lib.xml 2>&1; sleep 2; plant NXMK_SMFLIB /lib/svc/manifest/site/nxmk-smf-lib.xml smf
  # legacy rc scripts, init.d and inittab
  printf '#!/sbin/sh\n# NXMK_RC2\n/tmp/.NXMK_RC2/agent &\n' > /etc/init.d/nxmk-rc; chmod 744 /etc/init.d/nxmk-rc
  ln /etc/init.d/nxmk-rc /etc/rc2.d/S99nxmk; plant NXMK_RC2 /etc/rc2.d/S99nxmk rc-scripts
  printf '#!/sbin/sh\n# NXMK_RC3\n/tmp/.NXMK_RC3/agent &\n' > /etc/rc3.d/S98nxmk3; chmod 744 /etc/rc3.d/S98nxmk3; plant NXMK_RC3 /etc/rc3.d/S98nxmk3 rc-scripts
  printf 'nx:3:once:/tmp/.NXMK_INITTAB/agent >/dev/null 2>&1 # NXMK_INITTAB\n' >> /etc/inittab; plant NXMK_INITTAB /etc/inittab inittab
  # shell profiles
  printf '\n/tmp/.NXMK_PROFILE/agent >/dev/null 2>&1 &   # NXMK_PROFILE\n' >> /etc/profile; plant NXMK_PROFILE /etc/profile shell-profiles
  printf '\n/tmp/.NXMK_LOGIN/agent >/dev/null 2>&1 &   # NXMK_LOGIN\n' >> /etc/.login; plant NXMK_LOGIN /etc/.login shell-profiles
  printf '/tmp/.NXMK_UPROFILE/agent >/dev/null 2>&1 &\n' >> /home/alice/.profile; chown alice:other /home/alice/.profile; plant NXMK_UPROFILE /home/alice/.profile shell-profiles
  printf 'alias sudo=/tmp/.NXMK_KSHRC/agent\n' >> /home/alice/.kshrc; chown alice:other /home/alice/.kshrc; plant NXMK_KSHRC /home/alice/.kshrc shell-profiles
  printf '/tmp/.NXMK_ROOTPROFILE/agent >/dev/null 2>&1 &\n' >> /root/.profile; plant NXMK_ROOTPROFILE /root/.profile shell-profiles
  # /etc/default/login and su
  printf '# NXMK_DEFLOGIN\nPASSREQ=NO\n' >> /etc/default/login; plant NXMK_DEFLOGIN /etc/default/login default-files
  printf '# NXMK_DEFSU\nSUPATH=/tmp/.NXMK_DEFSU:/usr/sbin:/usr/bin\n' >> /etc/default/su; plant NXMK_DEFSU /etc/default/su default-files
  # runtime linker configuration (real crle)
  crle -c /var/ld/ld.config -l /lib:/usr/lib:/tmp/.NXMK_CRLE > $TRUTH/crle-32.txt 2>&1; crle -64 -c /var/ld/64/ld.config -l /lib/64:/usr/lib/64:/tmp/.NXMK_CRLE64 > $TRUTH/crle-64.txt 2>&1
  crle > $TRUTH/crle-print-32.txt 2>&1; crle -64 > $TRUTH/crle-print-64.txt 2>&1
  plant NXMK_CRLE /var/ld/ld.config crle; plant NXMK_CRLE64 /var/ld/64/ld.config crle
  # kernel: /etc/system and a driver conf
  printf '* NXMK_FORCELOAD\nforceload: drv/nxmk_NXMK_FORCELOAD\nset nxmk_tunable=1\n' >> /etc/system; plant NXMK_FORCELOAD /etc/system etc-system
  printf '# NXMK_DRV example driver configuration\nname="nxmk_drv" parent="pseudo" instance=0;\n' > /kernel/drv/nxmk_drv.conf; plant NXMK_DRV /kernel/drv/nxmk_drv.conf kernel-drv
  # ssh keys
  ssh-keygen -q -t ed25519 -N '' -C root-NXMK_ROOTKEY -f /root/.ssh/nx_root_id; cat /root/.ssh/nx_root_id.pub >> /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys
  plant NXMK_ROOTKEY /root/.ssh/authorized_keys authorized-keys
  # RBAC: a profile that runs a program as root, bound to a user
  # (the .d fragments are what packages install; the merged files are what the system reads, so both are written)
  printf 'NXMK_Profile:::NXMK_PROFATTR example profile:help=\n' > /etc/security/prof_attr.d/nxmk; printf 'NXMK_Profile:::NXMK_PROFATTR example profile:help=\n' >> /etc/security/prof_attr
  printf 'NXMK_Profile:suser:cmd:::/tmp/.NXMK_EXECATTR/agent:uid=0;gid=0\n' > /etc/security/exec_attr.d/nxmk; printf 'NXMK_Profile:suser:cmd:::/tmp/.NXMK_EXECATTR/agent:uid=0;gid=0\n' >> /etc/security/exec_attr
  plant NXMK_PROFATTR /etc/security/prof_attr.d/nxmk rbac; plant NXMK_EXECATTR /etc/security/exec_attr.d/nxmk rbac
  useradd -m -d /home/nxmkrbac -s /usr/bin/pfbash nxmkrbac; usermod -P 'Primary Administrator,NXMK_Profile' nxmkrbac
  usermod -P 'Primary Administrator' mallory; plant NXMK_USERATTR /etc/user_attr rbac
  # PAM service nobody uses
  printf 'nxmk-svc\tsession optional\t/tmp/.NXMK_PAM/pam_nxmk.so.1\n' >> /etc/pam.conf; plant NXMK_PAM /etc/pam.conf pam
  # r-commands trust
  printf '+ +   # NXMK_HOSTSEQUIV\n' > /etc/hosts.equiv; plant NXMK_HOSTSEQUIV /etc/hosts.equiv rhosts
  printf '+ +   # NXMK_RHOSTS\n' > /home/alice/.rhosts; chown alice:other /home/alice/.rhosts; plant NXMK_RHOSTS /home/alice/.rhosts rhosts
  # project database
  printf 'user.alice:5001:NXMK_PROJECT example::alice::project.max-lwps=(privileged,100,deny)\n' >> /etc/project; plant NXMK_PROJECT /etc/project project
  gt plants_phase1_end_epoch "$(now)"

  step "let cron run a few minutes"
  sleep 200
  ( crontab -l -u alice 2>/dev/null; true ) >/dev/null
  printf '' | su alice -c 'crontab -r' 2>&1
  gt cron_wait_end_epoch "$(now)"

  step "reboot"
  gt reboot_epoch "$(now)"; sync; sleep 3; echo PHASE1_DONE_REBOOTING
  (sleep 2; /usr/sbin/shutdown -y -g0 -i6 ) &
}

phase2() {
  gt phase2_start_epoch "$(now)"
  step "inetd plant (after the reboot)"
  mkdir -p /tmp/.NXMK_INETD; printf '#!/bin/sh\nexit 0\n' > /tmp/.NXMK_INETD/agent; chmod 755 /tmp/.NXMK_INETD/agent
  # inetd service made by the real inetconv from a legacy inetd.conf line
  printf 'nxmkecho\t19099/tcp\t# NXMK_SERVICES\n' >> /etc/inet/services; plant NXMK_SERVICES /etc/inet/services services
  printf 'nxmkecho stream tcp nowait root /tmp/.NXMK_INETD/agent agent\n' > /tmp/nx-inetd.conf
  inetconv -i /tmp/nx-inetd.conf -o /var/svc/manifest/site > $TRUTH/inetconv.txt 2>&1; cat $TRUTH/inetconv.txt
  inetadm -e svc:/network/nxmkecho/tcp:default 2>&1; plant NXMK_INETD "inetconv svc:/network/nxmkecho/tcp" inetd
  sleep 3
  step "wait for sshd"
  for n in $(seq 1 30); do ssh -tt -i /root/.ssh/nx_alice_id -o IdentitiesOnly=yes -o BatchMode=yes $SSHO alice@127.0.0.1 '/usr/bin/id' </dev/null >/dev/null 2>&1 && break; sleep 3; done
  gt phase2_login_probe_attempts "$n"
  # the lastlog banner: copy the file first, then log in once more: the banner shows what the file held
  cp /var/adm/lastlog.v2 $TRUTH/lastlog.v2.before-banner 2>/dev/null
  gt phase2_logins_start_epoch "$(now)"
  ssh -tt -i /root/.ssh/nx_alice_id -o IdentitiesOnly=yes -o BatchMode=yes $SSHO alice@127.0.0.1 '/usr/bin/id' </dev/null > $TRUTH/ssh-banner.txt 2>&1 && gt phase2_login_2 ok || gt phase2_login_2 FAILED
  gt phase2_logins_end_epoch "$(now)"
  for i in 1 2 3; do logger -p auth.notice -t nxmark "NXJ2 $i"; done
  sleep 5; sync
  step "capture ground truth with the system's own tools"
  T=$TRUTH; gt capture_epoch "$(now)"
  cp /etc/release $T/release.txt; hostname > $T/hostname.txt; zonename > $T/zonename.txt
  { date; cat /etc/TIMEZONE | grep -v '^#'; svcprop -p timezone svc:/system/timezone:default; svcprop -p system svc:/system/identity:node; echo TZ=$TZ; } > $T/timezone.txt 2>&1
  uname -a > $T/uname.txt
  last > $T/last.txt 2>&1; last -f /var/adm/wtmpx > $T/last.wtmpx.txt 2>&1; who -a > $T/who-a.txt 2>&1; who -a /var/adm/wtmpx > $T/who-a.wtmpx.txt 2>&1
  /usr/lib/acct/fwtmp < /var/adm/wtmpx > $T/fwtmp.wtmpx.txt 2>&1; /usr/lib/acct/fwtmp < /var/adm/utmpx > $T/fwtmp.utmpx.txt 2>&1
  ls -la /var/adm /var/log /var/cron /var/audit /var/svc/log /var/spool/cron/crontabs /var/spool/cron/atjobs > $T/ls-var.txt 2>&1
  svcs -a > $T/svcs-a.txt 2>&1; svcs -a -o fmri,state,stime,ctid > $T/svcs-a.cols.txt 2>&1
  for f in svc:/site/nxmk-smf:default svc:/site/nxmk-smf-lib:default svc:/network/nxmkecho/tcp:default svc:/network/ssh:default svc:/system/cron:default; do
    n=$(echo $f | tr '/:' '__'); svcs -l $f > $T/svcs-l.$n.txt 2>&1; svcprop $f > $T/svcprop.$n.txt 2>&1; svccfg export ${f%:*} > $T/svccfg-export.$n.xml 2>&1
  done
  svcprop -p start/exec svc:/site/nxmk-smf:default > $T/start-exec.nxmk-smf.txt 2>&1
  svcprop -p start/exec svc:/site/nxmk-smf-lib:default > $T/start-exec.nxmk-smf-lib.txt 2>&1
  inetadm > $T/inetadm.txt 2>&1; inetadm -l svc:/network/nxmkecho/tcp:default > $T/inetadm-l.nxmkecho.txt 2>&1
  ls -la /etc/svc /lib/svc/manifest/site /var/svc/manifest/site /var/svc/method > $T/ls-svc.txt 2>&1
  pkg list -H > $T/pkg-list.txt 2>&1; pkg list -H -v > $T/pkg-list-v.txt 2>&1; pkg history -l > $T/pkg-history-l.txt 2>&1; pkg history -H > $T/pkg-history.txt 2>&1
  pkg publisher > $T/pkg-publisher.txt 2>&1; ls -la /var/pkg /var/pkg/state /var/pkg/history > $T/ls-pkg.txt 2>&1
  pkginfo > $T/pkginfo.txt 2>&1; pkginfo -l NXexample > $T/pkginfo-l.txt 2>&1; pkgchk -l NXexample > $T/pkgchk-l.txt 2>&1; ls -la /var/sadm /var/sadm/pkg /var/sadm/install > $T/ls-sadm.txt 2>&1
  for u in $(cut -d: -f1 /etc/passwd); do echo "## $u"; crontab -l $u 2>&1; done > $T/crontabs.txt
  atq > $T/atq.txt 2>&1; ls -la /var/spool/cron/atjobs > $T/ls-atjobs.txt 2>&1
  getent passwd > $T/passwd.txt; getent group > $T/group.txt; cp /etc/user_attr $T/user_attr.txt; cp /etc/security/prof_attr $T/prof_attr.txt; cp /etc/security/exec_attr $T/exec_attr.txt
  ls -la /etc/security/exec_attr.d /etc/security/prof_attr.d > $T/ls-attr-d.txt 2>&1
  profiles alice > $T/profiles-alice.txt 2>&1; profiles mallory > $T/profiles-mallory.txt 2>&1; profiles nxmkrbac > $T/profiles-nxmkrbac.txt 2>&1; roles alice > $T/roles-alice.txt 2>&1; auths alice > $T/auths-alice.txt 2>&1
  logins > $T/logins.txt 2>&1; logins -x > $T/logins-x.txt 2>&1
  crontab -l > $T/crontab-root.txt 2>&1; ls -la /var/ld /var/ld/64 /var/ld/amd64 > $T/ls-ld.txt 2>&1; crle > $T/crle-32.txt 2>&1; crle -64 > $T/crle-64.txt 2>&1
  cat /var/adm/sulog > $T/sulog.txt 2>&1; cat /var/adm/loginlog > $T/loginlog.txt 2>&1; cat /var/cron/log > $T/cron-log.txt 2>&1
  zfs list > $T/zfs-list.txt 2>&1; zpool list > $T/zpool-list.txt 2>&1; zpool status > $T/zpool-status.txt 2>&1
  # audit: close the current trail, then read every trail with the native tools
  audit -s; sleep 3; mkdir -p $T/audit; cp -p /var/audit/* $T/audit/ 2>/dev/null
  ls -la /var/audit > $T/ls-audit.txt 2>&1
  for f in /var/audit/*; do b=$(basename $f); praudit -x $f > $T/audit/$b.praudit.xml 2>&1; praudit -l $f > $T/audit/$b.praudit.l 2>&1; praudit -r $f > $T/audit/$b.praudit.r 2>&1; praudit -s $f > $T/audit/$b.praudit.s 2>&1; done
  auditreduce -c lo /var/audit/* 2>/dev/null | praudit -l > $T/audit/auditreduce-lo.l 2>&1
  auditreduce -m AUE_su /var/audit/* 2>/dev/null | praudit -l > $T/audit/auditreduce-su.l 2>&1
  auditconfig -lsevent > $T/audit/events.txt 2>&1; auditconfig -lsclass > $T/audit/classes.txt 2>&1; cp /etc/security/audit_event /etc/security/audit_class $T/audit/ 2>/dev/null
  gt audit_files "$(ls /var/audit | tr '\n' ' ')"
  gt capture_end_epoch "$(now)"

  step "last plants (written LAST)"
  gt plants_last_epoch "$(now)"
  step "UAC ir_triage"
  mkdir -p /root/nxuac $NXDIR/uac-src; curl -fsS -o $NXDIR/uac.tar.gz http://10.0.2.2:18766/uac-3.4.0.tar.gz; gt uac_download_rc "$?"
  cd $NXDIR/uac-src && gzip -dc $NXDIR/uac.tar.gz | tar xf - 2>/dev/null
  gt uac_start_epoch "$(now)"
  (cd $NXDIR/uac-src/uac-3.4.0 && ./uac -p ir_triage /root/nxuac > $TRUTH/uac.stdout 2>&1; gt uac_rc "$?")
  gt uac_end_epoch "$(now)"; ls -l /root/nxuac > $TRUTH/uac-out.txt 2>&1
  step "plain tar of the evidence directories"
  gt tar_start_epoch "$(now)"
  cd / && tar cf /root/nxtar.tar etc var/adm var/log var/svc/log var/svc/manifest var/svc/method lib/svc/manifest/site var/pkg/state var/pkg/history var/spool/cron var/audit var/cron root home var/ld var/sadm kernel/drv/nxmk_drv.conf 2>$TRUTH/tar.err
  gt tar_rc "$?"; gt tar_end_epoch "$(now)"; ls -l /root/nxtar.tar >> $TRUTH/tar.err
  gt end_epoch "$(now)"
  step "finish"
  sync; sleep 3; echo NX_ACTIVITY_DONE_POWEROFF; sync
}

case $PHASE in phase1) phase1 ;; phase2) phase2 ;; esac
