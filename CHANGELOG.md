# Changelog

Every change to the output contract ([docs/OUTPUT.md](docs/OUTPUT.md)) is listed here:
field names, file layout, manifest schema, exit codes.

## 0.1.0 (unreleased)

First version.

- Commands: `auto-parse`, `parse`, `super-timeline`, `persistence-hunter`, `list`.
- Inputs: directories, `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.zst`, `.tar.xz`, `.zip`, raw and E01 disk
  images (ext4, XFS, APFS, Btrfs, ZFS).
- Disk images: UFS1 and UFS2 (FreeBSD, NetBSD and OpenBSD FFS, Solaris UFS, either byte order), and
  the partitions inside BSD disklabels and Solaris VTOCs; new partition type names (`freebsd_ufs`,
  `freebsd_swap`, `netbsd_ffs`, `openbsd_data`, `solaris_root`, ...). A label's partitions are
  numbered `100 * slice + n` (`p101` is slice 1, partition `a`).
- NUL padding at the start of a log line is skipped, so the line after it is parsed.
- `dnf-log`: scriptlet output lines take the time of the line before them.
- `web-error-log`: a line in no server format is kept as a message with no time.
- `syslog` also reads `var/log/ufw.log*`.
- `auth-log` also reads `var/log/messages*` and outputs the lines there that are auth events
  (Alpine, SUSE). The `syslog` artifact still outputs every line of that file.
- New artifacts: `wtmpdb` and `lastlog2` (the SQLite login records of Debian 13 and openSUSE
  Tumbleweed), `dnf5-log` (Fedora).
- `lastlog` and `utmp`: the aarch64 record layout is recognized from the file length, so a
  file with one record is read correctly.
- `live-open-files` reads BusyBox `lsof` output (Alpine).
- The host's OS version falls back to `system-release`, `lsb-release`, `debian_version` and
  `alpine-release` when `os-release` was not collected.
- `journald`: three new fields, `event`, `user` and `remote_address`. A message that is an
  authentication event (ssh, sudo, su, PAM, account changes) is classified as `auth-log`
  classifies it, and its timeline event has that name instead of `log`. Hosts with no syslog
  daemon (Debian 12 and later, Fedora, Arch) have these events only in the journal.
- `auth-log`: new event `group_member_added` (`usermod`, `gpasswd`).
- Solaris and illumos hosts (OmniOS verified; Oracle Solaris from documentation): new artifacts `wtmpx`, `utmpx`,
  `solaris-lastlog`, `sulog`, `loginlog`, `cron-log`, `smf-repository` (SQLite 2.1), `smf-manifests`, `smf-logs`, `ips-history`,
  `ips-packages`, `svr4-pkginfo`, `svr4-contents`, `solaris-shadow`, `user-attr`, `rbac-profiles`, `project`, `solaris-at-jobs`,
  `inittab`, `rc-scripts`, `etc-system`, `default-files`, `crle-config`, `kernel-drv`, `pam-conf` and `rhosts`;
  23 persistence-hunter checks for them. New timeline events: `shutdown`, `service_method`, `service_state`.
- `auth-log` and `syslog` also read `var/adm/messages*` (and `var/log/authlog*`), and `auth-log` classifies the `[ID n auth.info]`
  prefix and the `su` and `login` phrases of Solaris. The host's name, version and zone come from `etc/nodename`, `etc/release` and `etc/default/init`.
- macOS, new artifacts (all synthetic-only, see `docs/LIMITATIONS.md`): `powerlog`,
  `crash-reports`, `rosetta-aot`, `netusage`, `dhcp-leases`, `network-interfaces`, `url-cache`,
  `binary-cookies`, `hsts`, `shared-file-lists`, `finder-prefs`, `dock-items`, `login-window`,
  `spotlight-shortcuts`, `ds-store`, `auth-db`, `exec-policy`, `pkg-receipts`, `config-profiles`,
  `application-firewall`, `bluetooth-devices`, `time-machine`, `lockdown-pairings`,
  `startup-items`, `legacy-rc`, `folder-action-scripts`, `system-plugins`, `messages`,
  `mail-envelopes`, `call-history`. New timeline events: `crashed`, `rosetta_translated`,
  `authdb_rule_changed`, `message`, `mail`, `call`.
- `sudoers`, `sshd-config` and `pam` also read `private/etc/...` on macOS (their OS set is now every system); `bash-history` reads
  `.bash_sessions`. `persistence-hunter` has ten new macOS checks (login and logout hooks,
  re-opened applications, `auth.db`, StartupItems, rc files, Folder Actions, authorization
  plug-ins, root-certificate profiles).
- `at-jobs` reads `var/spool/atd` (Arch, Alpine).
- `bodyfile`: a UAC line with no creation time is read instead of warned about.
- `auth-log`: new event `auth_failure` for PAM's "authentication failure" lines (user and
  remote host); the old `sshd(pam_unix)` program form and rsyslog's "message repeated N
  times" are classified too.
- `wtmp`, `btmp`, `utmp` and `lastlog` written by a big-endian host (s390x) are read.
- The OS version falls back to any `etc/*-release` file of the distribution.
- A UAC collection wrapped in another archive is read.
- An ext3/ext4 volume imaged while in use has its journal replayed in memory, as the kernel does on
  mount. A warning says how much was replayed, or why the journal was not or only partly replayed.
- CatScale collections are read: the archives inside them become one host.
- An ext4 volume imaged while in use is named in a warning (its journal is not replayed).
- CatScale collections are read: the archives inside them become one host, and its `ps`,
  `ss`/`netstat`, `lsof` and `lsmod` output is read by `live-processes`, `live-network`,
  `live-open-files` and `live-modules` (which gain `netstat -o` timers and the `lsof -R` parent pid).
- `auto-parse -d` also opens archives and images up to three levels down (fastir writes
  `<folder>/<run>/<host>-files.zip`) when the folder holds no host itself.
- Docker and Podman artifacts find a moved data root (`data-root`, `--root`) by the layout below it.
- New artifacts: `containerd-images` (Docker 29 and Kubernetes image store, BoltDB), `dmesg`,
  `cloud-init-log`, `cloud-init-output`, `cloud-init-user-data`, `alternatives-log`,
  `unattended-upgrades-log`, `dnf-debug-log`, `zypper-log`, `zypp-history`.
- A compressed tar of 2 GiB or more is streamed from the file instead of memory-mapped, which
  took the resident size of a 2.9 GB UAC collection from 7.1 GB to 4.3 GB.
- Evidence in which no host is found is an error (exit code 2), not an empty successful run.
- A zip member dated 1980-01-01 (no time recorded) no longer sets the year of the log lines
  in it; such lines get no time.
- The fallback host name is the evidence file's name without its archive extension.
- A raw image split into `.001`, `.002`... is read as one disk.
- Compressed raw images and Btrfs, F2FS and NTFS volumes are named in the error or warning
  instead of "not a disk image".
- qcow2 (2 and 3, compressed, extended L2), VMDK (sparse, `streamOptimized`, flat and split),
  VHD (fixed and dynamic), VHDX and VDI virtual machine disks are read directly. Disks that need a
  backing file or parent, or a key, are refused with the reason.
- Virtual machine disks, compressed raw images and F2FS and NTFS volumes are named in
  the error or warning instead of "not a disk image".
- XFS: a symlink target longer than one block is read (one header per extent).
- LVM2: linear logical volumes in disk images are read and listed as `<vg>-<lv>` (see [docs/LIMITATIONS.md](docs/LIMITATIONS.md)).
- Linux software RAID (md, metadata 0.90 and 1.x): linear, RAID0, RAID1, RAID10 (near), RAID4/5 (one missing member is rebuilt) and RAID6 arrays are assembled from the members in an image, or from the images beside the evidence file when an array was acquired one image per disk, and read like a partition, LVM2 on top included (see [docs/LIMITATIONS.md](docs/LIMITATIONS.md)).
- One host per disk: the volumes that a root filesystem's `/etc/fstab` mounts (`/boot`, `/var`, `/home`, on partitions, logical volumes or arrays) are listed under the root, with their files in its single body file, instead of as hosts of their own.
- `super-timeline --start` and `--end` limit the timeline to a time window.
- bzip2: `.bz2` log rotations and `.tar.bz2` archives are read.
- `rpm-db` reads the BerkeleyDB hash database (`/var/lib/rpm/Packages`, RHEL 7 and
  Amazon Linux 2, either byte order) as well as SQLite.
- Biome SEGB v2: entries start on a 4-byte boundary, found by checking real files.
- Manifest `schema_version` 1.
- Timeline run file format version 2 (sorted events plus a sparse index).
- New artifacts: `systemd-enablement` (enablement links, masks, aliases and lingering users),
  `motd-scripts`, `nm-dispatcher`, `systemd-generators`, `env-config`, `logrotate-scripts`
  and `sshd-config`. `modules-load` has a new field `module_in_kernel_tree`. Artifacts can
  now read links and empty files themselves (`Artifact::presence`).
- `persistence-hunter` joins enablement links and timers to unit records (the `evidence`
  column of a systemd unit record gains a `joined` object), ranks enabled units first within a
  severity, and has 16 new check ids. Stock `/etc/bashrc`, `modprobe.d`, `pam.d/login` and
  `rc.local` lines and the cloud-init sudo rule no longer raise medium findings.
- Package records for more distributions: new artifacts `pacman-log` and `pacman-db` (Arch),
  `apk-installed` and `apk-world` (Alpine), `zypp-history` (SUSE), `emerge-log` and `portage-db`
  (Gentoo), `xbps-pkgdb` (Void), `tdnf-history` (Photon), `yum-history` and `yumdb` (CentOS 6
  and 7, Oracle Linux 7, Amazon Linux 1) and `alternatives-log`. Their package events use the
  existing names `package_installed`, `package_upgraded` and `package_removed`; commands that
  changed packages are `package_command`, repository changes `repository_added` and
  `repository_removed`, and `update-alternatives` runs `alternative_changed`.
- `rpm-db` also reads SUSE's ndb database (`Packages.db`, in `usr/lib/sysimage/rpm` and
  `var/lib/rpm`) and the BerkeleyDB `Packages` file in `usr/lib/sysimage/rpm` (Leap 15.6).
- Btrfs volumes in disk images are read (single-device; zlib, LZO and zstd compression), shown
  as the system mounts them: the root subvolume plus the subvolumes `/etc/fstab` mounts.
  Read-only snapshots are listed as empty directories (see [docs/LIMITATIONS.md](docs/LIMITATIONS.md)).
- New Linux artifacts for execution and failed-login evidence: `pacct` (process accounting, one
  record per finished process, event `executed` at the start time; versions 3, 2 and 0, either
  byte order), `coredump` (systemd-coredump file names, event `crashed`), `apport-crash`,
  `abrt-problem`, `kernel-crash`, `sudo-io`, `sudo-log`, `sudo-timestamps`, `sudo-lectured`,
  `faillock`, `tallylog`, `faillog` (event `failed_login`), `opasswd`, and `sysstat` (CPU, memory,
  load, process creation, network and disk per interval, sysstat 12.x files only).
- `tool-history`: the histories of node, psql, sqlite3, redis-cli, irb, PHP, gdb, mongo, mongosh and
  PowerShell in one artifact. `bash-history` also reads macOS `~/.bash_sessions/*.history`.
- New timeline events: `crashed`, `activity_restart`, `sudo_denied`, `sudo_exit`,
  `sudo_authenticated`, `sudo_lectured`.
- FreeBSD, OpenBSD and NetBSD hosts are found and read (host name and release from `rc.conf`,
  `etc/myname`, the `freebsd-update` tag, `etc/release` or a UAC `uname -a`). New artifacts:
  `utx` (FreeBSD login records), `bsd-utmp`, `bsd-lastlog` and `netbsd-utmpx` (OpenBSD and NetBSD),
  `pkg-db` (FreeBSD `local.sqlite`), `pkg-add-db` (OpenBSD), `pkg-log` (`pkg` lines of
  `messages`), `userlog` (FreeBSD account changes), `master-passwd`, `doas-conf`, `rc-conf`,
  `rc-d`, `bsd-rc-local`, `bsd-at-jobs`, `loader-conf`, `ttys`, `devd-conf`, `jail-conf` and
  `login-conf`.
- New artifact `bsm-audit`: BSM audit trails (`var/audit/*`) of FreeBSD and macOS, with the event
  names chosen by the host's operating system, and the Solaris paths registered.
- `auth-log` reads `var/log/authlog*` and the BSD forms of `doas`, `su` and `login` messages
  (events `sudo_command`, `sudo_failure`, `su`, and the new `login`; a failed console login is `auth_failure`).
  `syslog` also reads the other BSD logs (`security`, `daemon`, `devd.log`, `xferlog`,
  `dmesg.today`, `setuid.today`, `daily.out`...). `cron`, `cron-scripts`, `shell-profiles` and
  `sudoers` read the BSD paths (`var/cron/tabs/*`, `.cshrc`, `.shrc`, `usr/local/etc/sudoers.d/*`).
- `persistence-hunter`: 15 checks for the new artifacts (`rc-local`, `rc.d` and `rc.conf`
  services, boot loader modules, `ttys`, `doas`, `devd`, jails, `master.passwd`, at jobs); the
  stock BSD `toor` account is not reported as a second uid 0.
- ZFS pools in disk images are read (single disk, mirror, stripe and RAID-Z members in one image;
  lz4, lzjb, zle, gzip and zstd; pool version 28 and feature-flag pools), shown as the system
  mounts them: the boot environment as `/` and every other dataset at its mountpoint. GPT
  partitions of type `freebsd_zfs` and `zfs` are named so.
- Desktop activity: new artifacts `gtk-recent-files` (`recently-used.xbel`), `trash`
  (`.trashinfo` paired with the trashed file; event `file_trashed`), `thumbnails` (freedesktop
  thumbnails, read from the PNG text chunks only), `usb-devices` (attach and disconnect from
  kernel lines in syslog and `dmesg` files), `cups-page-log` and `cups-jobs` (the print log and the
  IPP job control files), `remmina-profiles` and `filezilla-servers` (never the password).
- Browsers: new artifacts `chromium-cookies`, `chromium-logins`, `chromium-extension-settings`,
  `chromium-extensions`, `firefox-extensions`, `firefox-logins`, `firefox-cookies`,
  `firefox-prefs`, `firefox-user-js` and `firefox-session` (`mozlz4`). Cookie values, saved
  passwords and user names are never read. The Chromium and Firefox artifacts also find Flatpak
  profiles; the Chromium ones also Brave's snap profile.
- Service logs: new artifacts `mail-log` (Postfix, Dovecot, Exim; events `mail_login`,
  `mail_auth_failure`, `mail_sent`, `mail_received`, `mail_failed`, `mail_rejected`),
  `postgres-log` (stderr, csvlog, jsonlog), `mysql-error-log`, `mysql-general-log`,
  `mysql-slow-log`, `haproxy-log`, `squid-access-log`, `squid-cache-log`, `named-query-log`,
  `fail2ban-log`, `dhcpd-leases`, `dhclient-leases`, `vsftpd-log`, `xferlog`, `samba-log`,
  `samba-audit`, `modsec-audit-log` and `tomcat-log`. `web-access-log` also reads Tomcat's
  `localhost_access_log` and CUPS's `access_log`. SQL `PASSWORD` and `IDENTIFIED BY` literals in
  statement logs are replaced.
- New artifacts for Kubernetes nodes: `k8s-pod-logs`, `k8s-manifests` (static pods and k3s
  auto-applied manifests), `kubelet-config`, `kubeconfig`, `cni-config`, `k8s-audit`, and
  `containerd-containers` (container and sandbox records from containerd's `meta.db`).
- New artifacts for cloud agents: `ssm-agent-log`, `waagent-log`, `cloud-remote-exec` (SSM Run
  Command and Session Manager files, Azure extension settings and downloads), `azure-provisioning`,
  and `credential-files` (which cloud and developer credential files exist and for whom; never
  a secret).
- New artifacts for remote-access tools: `remote-access-config` (AnyDesk, TeamViewer, RustDesk,
  MeshAgent, ngrok, cloudflared, Tailscale, ZeroTier, frp, WireGuard, OpenVPN, VS Code tunnels
  and extensions), `remote-access-log` and `remote-sessions`.
- `persistence-hunter`: new checks `k8s-static-pod-unexpected`, `k8s-static-pod-host-access`,
  `k3s-auto-apply-not-stock`, `kubelet-anonymous-auth`, `kubelet-authorization-always-allow`,
  `remote-tool-autostart`, `ssh-tunnel-command`, `remote-access-tool-present`,
  `tunnel-exposes-local-service`, `vscode-tunnel-service-account` and `vpn-hook-suspicious`.
- VMware ESXi: hosts are recognised from `etc/vmware/esx.conf`, `hostd` files or a `uac-<host>-esxi-` name,
  named from `esx.conf` or `etc/hosts`, and read from a `vm-support` bundle (its `.FRAG-` pieces are repaired)
  or a UAC collection. New artifacts: `esxi-shell`, `esxi-hostd`, `esxi-vob`, `esxi-vmkernel`,
  `esxi-daemon-log`, `esxi-syslog`, `esxi-auth-log`, `esxi-vm-log`, `esxi-sysboot`, `esxi-vib`, `esxi-vib-list`,
  `esxi-config`, `esxi-host-config`, `esxi-vm-inventory`, `esxi-permissions`, `esxi-firewall-rules`,
  `esxi-rc-local`, `esxi-rc-local-files`, `esxi-live-connections`, `esxi-live-processes`,
  `esxi-live-vm-processes`, `esxi-live-vm-list`; new timeline events `vm_power_on`, `vm_power_off`,
  `vm_registered`, `vm_removed`, `vm_created`, `vm_snapshot`, `account_locked`, `service_changed`, `shutdown`,
  `shell_session`, `ssh_enabled`, `ssh_disabled`, `shell_enabled`, `shell_disabled`, `cron_executed`,
  `sftp_write`, `sftp_remove`, `audit` and `problem`. `persistence-hunter` gains eight ESXi checks.
- `authorized-keys` reads `etc/ssh/keys-<user>/` (ESXi), `bash-history` reads `/.ash_history` (ESXi), `shadow` also runs on ESXi.
  `syslog` and `auth-log` no longer run on ESXi, whose `syslog.log` and `auth.log` have their own layout.
- IBM AIX hosts are read (new `aix-*` artifacts; every format is synthetic only, see
  [docs/LIMITATIONS.md](docs/LIMITATIONS.md)): `aix-wtmp`, `aix-utmp`, `aix-failedlogin`,
  `aix-lastlog`, `aix-sulog`, `aix-cron-log`, `aix-security-passwd`, `-user`, `-group` and `-config`,
  `aix-inittab`, `aix-rc-scripts`, `aix-inetd-conf`, `aix-rhosts`, `aix-at-jobs`, `aix-sh-history`, `aix-smit`,
  `aix-audit-stream`, `aix-errpt`, `aix-lslpp`, `aix-rpm-db`, `aix-alog-output`, `aix-live-network`,
  `aix-live-rmsock`, `aix-lssrc` and `aix-genkex`. New timeline events: `su`, `failed_su` and
  `audit_event`; the others reuse `login`, `logout`, `failed_login`, `boot`, `last_login`,
  `password_changed`, `executed` and `package_installed`.
- On AIX, `syslog`, `shell-profiles` and `authorized-keys` also read AIX's paths (`var/adm/messages*`,
  `.profile` and `.ssh/authorized_keys` of root's home `/`, `.kshrc`), and `live-processes` reads
  AIX's two-word start times (`Mar 10`). The host name and the AIX level (`oslevel`) come from saved
  command output, and the zone from `TZ=` in `etc/environment`.
- `persistence-hunter`: eleven checks for AIX artifacts (`aix-inittab-*`, `aix-at-job*`, `aix-rc-suspicious`,
  `aix-inetd-*`, `aix-rhosts-*`, `aix-loader-hijack`, `aix-kernel-extension-in-temp`).
- `bsm-audit` reads Solaris and illumos trails: token version 2 (nanosecond times, no trailer token),
  event names from the host's own `etc/security/audit_event`, and four more tokens. New fields
  `users`, `privileges`, `authorizations` and `services`.
- Disk images: a NetBSD disklabel partition may reach past the MBR entry it is in (a filesystem
  grown in place), a grown UFS1 takes its size from the superblock's 64-bit field, and OpenBSD's
  `/usr` and `/home` join the root's host through the `<disk id>.<letter>` and `/dev/sd0d` names of
  its `fstab`. A volume that is recognised but cannot be opened is named with the reader's reason.
- A Linux host with `etc/release` and `etc/rc.d` (Mageia) is no longer taken for NetBSD: an
  `os-release` (even a link whose target was not collected) or a `uac-<host>-linux-` name decides.
- `waagent-log` reads the older `YYYY/MM/DD HH:MM:SS.ffffff` lines (agent 2.2); `postgres-log` reads
  the pre-10 default prefix (`%t `, no process id); `cups-page-log` and `web-access-log` ignore the
  one-line note CUPS leaves where its logs were; `xferlog` ignores FreeBSD's newsyslog line.
- `pam` skips `pam.d/README`; `cron` skips Solaris's `etc/cron.d/.proto`; `ips-packages` ignores the
  catalog's own `_` keys.
- The BSD console login failure is `auth_failure` (as PAM's), not `login_failed`.
