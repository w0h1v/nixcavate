# Limitations

What nixcavate does not do, and which parsers have not been checked against real data. Read
this before relying on a parser in a case.

## How each parser was checked

"Real tool" means the output was compared with the reference tool on the same file.
"Real data" means files written by the real software were parsed and checked by eye or by
count. "Synthetic" means fixtures were built from the published format description only: the
parser may be wrong where the description is.

| Checked against | Parsers |
|---|---|
| Real tool (ZFS) | ZFS reader, against OpenZFS 2.2 (`zpool import -o readonly=on`, mounted as the system boots: the `bootfs` dataset at `/`, `zfs mount -a`, `zfs` lines of `/etc/fstab`; `find`, `stat` and checksums): three real installs, the official FreeBSD 14.5 ZFS VM image (FreeBSD's `makefs`-built `zroot`, boot environment `ROOT/default` and ten mounted datasets, 43,363 entries), the same image after a first boot by FreeBSD's kernel (users and logs written, `freebsd-update` leaving a second boot environment, a new dataset, two snapshots: 45,036 entries and all 41,072 file checksums) and an OmniOS r151060 `rpool` written by illumos (a legacy-mounted boot environment, a snapshot, 70,251 entries), with the checksums of every file under `/etc`, `/var/log`, `/var/db`, `/root` and the home directories; 16 pools made with different `zpool create` and `zfs` options (compression off, lzjb, gzip, zstd, zle and lz4; 4 KiB records with large dnodes, 1 MiB records; ashift 9 with `copies=2`; `xattr=on` with `normalization=formD`; mirror, three-way stripe, RAID-Z1, RAID-Z2 and RAID-Z3; pool version 28 with a version-4 file system) filled with the edge-case tree, 250,096 entries and 200,736 file checksums: no difference. Ten small pools in the repository are compared field by field (inode, mode, owner, size, links, the four times to the nanosecond, content, link targets), among them boot environments, a clone, a legacy dataset, a zvol, an encrypted dataset, a mirror read from either side and a pool copied with records in its intent log |
| Real tool | journald (`journalctl -o json`: 1.5 million entries in the first check, then 10.8 million across four more hosts, 0 mismatches), Unified Log (`log show`, 119,650 entries, 99.9% of messages identical), ASL (`syslog -F raw`, 7,537 records), wtmp/btmp/utmp (`utmpdump`, x86-64 and aarch64), lastlog (`lastlog`), dpkg status (`dpkg-query`), rpm database (`rpm -qa`: SQLite on Rocky 9, BerkeleyDB on Amazon Linux 2 with 193 of 193 packages, big-endian BerkeleyDB on UBI 8 s390x with 184 of 184), SSH key fingerprints (`ssh-keygen -l`), ext4/XFS/APFS readers (`find`, `stat`, checksums of every file; ext4 and XFS also against a mount of eight distributions' official cloud images, 319,788 entries and 12,924 file checksums, and of 41 images made with different `mkfs` options and filled with edge cases, 640,000 entries and every file's checksum: no difference), UFS reader (FreeBSD's `stat` and `sha256sum` on a FreeBSD 14.5 mount: the official FreeBSD 14.5 UFS VM image, 43,360 entries and 39,167 file checksums with every field equal, and 17 images made by `newfs` and `makefs` with UFS1 and UFS2, 4 KiB to 64 KiB blocks, soft updates with and without journal, big-endian, and one copied while mounted, filled with edge cases, 195,961 entries and 3,535 file checksums, the only differences being the `.sujournal` file, which the unmount writes after the checksums were taken, and the UFS1 times FreeBSD changes when it loads them (see "Behavior to know"); illumos's GNU `stat` and `sha256sum` on three Solaris UFS images made by OmniOS `newfs`, logging and not, 8,892 entries, no difference but device nodes, which illumos shows with the device's size and whole-second times; OpenBSD 8.0's amd64 miniroot through its disklabel, no difference; NetBSD 11.1's live image (FFSv2ea, which FreeBSD does not mount) against NetBSD's own build manifests (`/etc/mtree/set.*`): 51,703 entries and 46,711 checksums, three differences, all in files the image's build sets up after the manifest (`etc/rc.conf`, and the modes of `dev/pts` and `etc/wpa_supplicant.conf`), not checked further), Btrfs reader (a kernel mount assembled as the system mounts it: two real installs, Fedora 45 with zstd compression and four subvolumes, and Arch, 89,956 entries and 4,275 file checksums; 15 images made with different `mkfs` and mount options, including zlib, LZO and zstd compression, 4 KiB and 64 KiB nodes, mixed block groups and holes without `no-holes`, filled with edge cases, 246,030 entries and 197,580 file checksums: no difference), ext3/ext4 journal replay (against the kernel's replay into a copy: two published volumes imaged while in use, ext4 and ext3, 209,220 entries and 166,958 file checksums, no difference; and six images copied while mounted, with checksummed and plain journals, a log that wraps, revoked blocks, a missing and a damaged commit block), LVM2 (a real Rocky 9 image against `lvm` and a mount: 37,724 of 37,724 files), software RAID (twenty-two small arrays made by `mdadm` 4.4 on a Linux 6.12 kernel: RAID1 in metadata 0.90, 1.0, 1.1 and 1.2, RAID0 with two chunk sizes and with unequal members in both layouts, RAID4, RAID5 in four layouts and in 0.90, RAID6, RAID10 near, RAID1 under LVM2, and three arrays over several image files, every file's sha256 equal to a real mount of the assembled array, and every RAID5 also with each member missing and RAID10 with members missing; a public two-disk CentOS 8 acquisition (two RAID1 arrays, LVM2 on one, `/boot` on the other) assembled and compared with `mdadm` and a mount: 1,608 of 1,608 file checksums, 122,054 of 122,055 listed entries equal in type, size, owner and time, the one other being the root directory), one host per disk (a GPT disk with `/boot`, `/var` on XFS and `/home` on LVM2 against a mount of the same layout, and eleven cloud images and virtual machines of the corpus, from Ubuntu, Rocky, AlmaLinux and Oracle Linux, whose separate `/boot` now joins the root's host instead of being a second one: the record count of every artifact other than the body file unchanged in all 24 images that open, and the body file's record count equal, or one fewer where both volumes list the `/boot/efi` mount point), E01 (`ewfacquire` images, byte-identical reads), InstallHistory (`plutil`), pacman local database and log (`pacman -Q`: 154 of 154 packages in a container and 193 of 193 with names and versions on a VM; the scripted `tree`, `jq`, `zip` installs and the `zip` removal at the logged seconds), Alpine apk database (`apk info`: 82 of 82 and, with versions, 248 of 248), SUSE ndb rpm database (`rpm -qa`: 181 of 181 on Leap 15, 188 of 188 on Tumbleweed, 196 of 196 and 182 of 182 on SLES 15 and 16, names, versions, releases and architectures) and the BerkeleyDB `Packages` of a Leap 15.6 VM (381 of 381), Gentoo vdb (312 of 312 `category/name-version`), Void xbps (70 of 70 `pkgver`), zypper history (scripted installs and removal at the logged seconds on five hosts), emerge log, yum history (scripted `yum` commands and package changes on a CentOS 7 VM and four older hosts), process accounting (`dump-acct` and `lastcomm` on kernel-written version 3 files from Debian 12, Ubuntu 24.04, Rocky 9 and CentOS 7 and on the same records converted by `dump-acct` to versions 2 and 0 and to the other byte order: 545 records, every field equal), pam_faillock (`faillock --user`: 24 of 24 entries on Debian 12, Rocky 9 and CentOS 7, including entries marked invalid), pam_tally2 (`pam_tally2 -u` on CentOS 7: 2 of 2 users), faillog (`faillog -a` on Debian 9 for arm64 and for 32-bit x86, whose records are 24 bytes, and on the disk of a public 2011 forensic challenge, 1 of 1, read with the 32-bit tool in an i386 container), systemd coredumps (3 files written by the real `systemd-coredump` 252 from kernel-written cores, against `coredumpctl list` and the journal's `COREDUMP_*` fields), apport (`apport-unpack`), sudo (`sudoreplay -l` and the real size of every stream: 22 sessions of sudo 1.8.23, 1.9.13 and 1.9.17, and the I/O log, classic log and JSON event log of each), `opasswd` (the algorithm of each hash of a real pam_pwhistory file, 7 of 7), sysstat (`sadf -j` of the same file, sysstat 12.5.4, 12.6.1 and 12.7.7: 36 real daily files of four hosts, 4,905 samples and 1,041,081 values equal within the digits sadf prints, and 94,705 disk rows) |
| Real data | Seventeen full systems run as virtual machines (Ubuntu 20.04 to 24.04, Debian 11 to 13, Rocky 8 and 9, AlmaLinux 9, CentOS 7 and Stream 10, Oracle Linux 9, Fedora, openSUSE Leap, Arch, Alpine), each with scripted activity across a reboot, read as a disk image and as a UAC collection and compared with the system's own tools: journald (86,545 entries, every field, in LZ4, XZ and zstd, compact and keyed-hash files), `audit.log` (34,636 records, raw and enriched), login records, package databases, snap and flatpak, root on LVM: equal; published evidence of real and training cases, from the disk of a public Linux forensics course: eight disk images (Ubuntu 14.04, 16.04 and 18.04, Debian 5, Kali, CentOS 7; ext3, ext4, XFS; E01, raw, VHD) and one UAC collection, 5.3 million records with no failed task (the journal file on a volume imaged while in use is read since the ext4 journal is replayed: 5,495 entries, as `journalctl` reads the file after the kernel's replay), two of the images compared with a mount (221,766 entries, no difference); a real `audit.log` (3,677 of 3,677 records); public auth logs (680,713 lines); the same scripted activity on 27 older and unusual distributions (CentOS 6 and 7, Ubuntu 14.04 to 22.04, Debian 8 to 12, Oracle Linux 7 to 9, Amazon Linux 1, SLES 15 and 16, Tumbleweed, Gentoo, Void, Photon, Kali, AlmaLinux) and on six CPU architectures (x86-64, i386, 32-bit ARM, ppc64le, riscv64 and big-endian s390x), login records compared one by one with `utmpdump` and `lastlog`: equal wherever the artifact is supported; the same scripted host (Debian 12 and Rocky 9) collected eleven ways (UAC as tar, zip and folder; CatScale; CyLR; Velociraptor; fastir; `tar`, `zip` and a folder of the root; `docker export`): the host is found in each and every check passes on what the tool collected; UAC collections of eleven containers (Amazon Linux 2 and 2023, Alpine, Arch, Debian 13, Fedora, openSUSE Leap, Rocky 8 and 9 on arm64 and x86-64, Ubuntu 24.04) with scripted logins, sudo, package changes and eleven persistence plants: every plant found, and logins, failed logins, last logins and package events equal to the script wherever the distribution writes the log; UAC collections of four Ubuntu servers (24.04 to 26.04; 49.5 million records, no failed task; syslog, auth.log, dpkg.log, dpkg status, passwd and group counts equal to the files' own), syslog, auth.log and secure (Debian 12, Rocky 9), dnf log and history (Rocky 9), apt history, dpkg log, shell and tool histories (bash, zsh, fish, vim, less, MariaDB), cron, at, systemd units, Docker and Podman files, Apache and nginx logs, UAC live response and body file, iptables and nftables, NetworkManager, Chromium and Firefox history, launchd plists, Background Task Management (a real store: 89 of 89 items), install.log, and five user stores of one Mac compared row by row with a direct query of the same file: TCC (295 of 295 rows), quarantine events (2,464 of 2,464), Safari history (39 of 39 visits), KnowledgeC (1,058 of 1,059), Biome SEGB v2 (214 files, 366,169 of 366,272 written entries decoded); log files the earlier runs left unparsed (the kernel ring buffer, cloud-init, update-alternatives, unattended-upgrades, dnf debug, zypper): every non-blank line of every real file is a record (67 files of the seventeen systems' UAC collections and 89 of four real hosts, no difference, no warning), and the cloud-init user data and logs of five of the virtual machines read as disk images equal a mount of the same image; Docker and Podman under a moved data root and containerd's image store, each against the daemon's own counts (`docker ps -a`, `docker logs`, `podman ps -a`, `ctr images ls`); failed-login and execution evidence of the public images: the faillog of a public 2011 forensic challenge (equal to the real tool's output), a real apport report of a Hadoop master (a `Package` report, read), 50 UAC collections of the scripted hosts (`faillog`, `tallylog` and `opasswd` present and empty or all zero: read without a warning, no records), and the four real hosts' 36 sysstat files; the logs of three published disk images that the first run could not read: an Azure agent log in the older `YYYY/MM/DD` form (2,248 lines), a PostgreSQL 9.3 log with the pre-10 default prefix (170 entries) and the one-line note CUPS leaves where its logs were |
| Real data (Kubernetes, cloud agents, remote access) | A real k3s server and a real kubeadm node (`kind`: kubeadm, kubelet, containerd, static pods), each run with a script (a deployment, an exec and a `kubectl cp` into a pod, a privileged pod with a `hostPath` of `/`, a CronJob, a DaemonSet, a failed image pull, a secret mount, a NodePort service, a deleted pod, a non-system user creating and deleting a pod and a role binding, anonymous requests) with an API audit policy, then the node's files copied out: pod and container logs (13 and 17 files, 124 and 909 lines; every record's namespace, pod, uid, container and restart count found in `crictl ps -a`, every physical line in exactly one record, the 40,000-byte line the runtime splits into `P` fragments joined into one message of 40,000 bytes), containerd metadata against `ctr -n k8s.io containers ls` (29 of 29 and 36 of 36 containers, 16 and 19 of them pod sandboxes: id, image and runtime; pod name, namespace, uid and container name equal to `crictl ps -a` and `crictl pods`), static pod and k3s manifests against `kubectl get pods -A -o json` (images, `hostNetwork`, `hostPID`, `privileged`, `hostPath` of every static pod and DaemonSet equal), the audit logs against a separate Python count of exec, secret-read, change and anonymous requests (106 and 422 lines; 0 differences), kubelet settings and kubeconfigs. Real AWS Systems Manager agent, Azure Linux agent (waagent) and Google guest agent installed and started in containers (they cannot reach their clouds: their start-up and failure logs are real); credential files made by the real `aws`, `kubectl`, `npm`, `git`, `vault` and `docker login` (against a real registry) with the secrets planted as `PLANTED-*` strings, compared with `aws configure list-profiles`, `kubectl config get-contexts`, `npm config list` and `docker login`: the names are equal and no secret reaches any output. Real AnyDesk, TeamViewer Host and RustDesk services started headless (ID and server compared with `anydesk --get-id`, `teamviewer info`), WireGuard (`wg-quick strip`), OpenVPN (its own log of the parsed `remote` lines), ZeroTier (`zerotier-cli listnetworks` and `info`), ngrok (`ngrok config check`), cloudflared (`ingress validate`, `ingress rule`), frp (`frpc verify`, TOML and INI), Tailscale joined to a real headscale server (`tailscale status --json`: hostname, tailnet, login, control URL), the VS Code server and CLI (the extensions its CLI reported installing). The four real hosts and the seventeen virtual machines of the corpus hold none of these files except Tailscale's unit files (the state file was not collected), so no number is claimed on them: the hunter rule for a tool started by a unit found `tailscaled.service` on each of the four hosts, as it should |
| Synthetic only (Kubernetes, cloud agents, remote access) | **The SSM Run Command orchestration tree, state documents and Session Manager files** (they exist only after a command ran from AWS: the layout follows AWS's documentation and published forensic write-ups; paths of other agent versions may differ), **Azure extension `*.settings`, `custom-script` and `run-command` downloads, `ovf-env.xml` and the log lines of an extension action** (WALinuxAgent only writes them when Azure sends them), **AnyDesk `connection_trace.txt` and TeamViewer `Connections_incoming.txt` lines** (they need a remote peer; the AnyDesk column order and TeamViewer's day-first date are from write-ups), **the log lines AnyDesk, TeamViewer and RustDesk write for an incoming session** (only the keywords the timeline selects on are a guess), **MeshAgent `.msh`, VS Code `code_tunnel.json`, cloudflared's `<tunnel-id>.json` credentials, RustDesk's `RustDesk2.toml`, the OpenVPN log in its classic time format** (and gcloud, Azure CLI, Terraform, OCI CLI, `.pypirc`, `.netrc` and `gh` credential files, in their documented formats because their tools need an account). The artifacts are conservative: a line or record that does not fit is a warning |
| Synthetic only | ESXi: see "VMware ESXi" below; yum.log, snap, flatpak, anacron timestamps, **Biome SEGB v1, FSEvents, Gatekeeper policy, dslocal accounts, known Wi-Fi networks, Safari downloads, emond, system extensions, managed preferences, Chromium and Firefox downloads**, **and every artifact in "macOS stores read from documentation only" below**, **every AIX parser except the one-line `errpt` listing and `lastlog` (see "IBM AIX" below)**, kernel crash dumps (`kernel-crash`: no kdump could be run in a container), the ABRT problem directories (no abrtd), `tool-history` for psql, redis-cli, irb, mongo, mongosh and PowerShell (the formats are plain readline lines; only node, sqlite3, gdb and PHP were written by the real tool), macOS `bash_sessions`, Remmina profiles, FileZilla server lists, Firefox `logins.json`, the rows of Chromium's `Login Data`, Exim authenticator lines, USB mass-storage and keyboard records, NetBSD disklabels inside an MBR partition that was never resized, Solaris SPARC VTOCs (with their tags) and big-endian Solaris UFS, a BSD disklabel on a disk with no partition table (real: FreeBSD `gpart` bsdlabels, OpenBSD's and NetBSD's disklabels, illumos x86 VTOCs, NetBSD and OpenBSD sparc64 Sun labels with big-endian UFS1), ZFS pools written by a big-endian host, Oracle Solaris 10 and 11 and SPARC files (see "Solaris and illumos") |

The macOS stores in bold are root-only, or had no entries on the Mac used for checking. No
real copy of them was used during development, so they are the least certain parsers in the
tool. Three carry specific doubts:

- **Biome v1.** Every real file checked was SEGB v2. The v1 layout follows public write-ups
  only. In v2, a deleted entry whose payload was wiped shows as hex without a warning.
- **FSEvents.** Two published tables of flag bits disagree. nixcavate uses the widely used
  community table and always outputs `flags_raw` beside the names.
- **ZFS pools written by a big-endian host** (SPARC Solaris, POWER). Every block carries its
  byte order and the reader reads both, but only small byte-swapped blocks built by hand were
  read: no real pool from such a host was available.
- **Firefox downloads.** No real download rows were available; state names follow the
  project's documentation. Chromium downloads were checked on a real row (see "Desktop
  activity, browsers and service logs").

## Desktop activity, browsers and service logs

Each artifact below was run against the real software in a throwaway container (Debian 12,
Ubuntu 24.04 or the project's official image, arm64), driven with real clients, and compared
with what the software or the driving script did. "Entries" are counted from the file's own
lines or from an independent reader (Python's `csv`, `sqlite3`), never from nixcavate.

| Artifact | Real software | Compared | Result |
|---|---|---|---|
| `mail-log` | Postfix 3.7.11 and Dovecot 2.3.19, Exim 4.96; Postfix 2.10.1 from a CentOS 7 guest | Logins, failed IMAP, POP3 and SMTP SASL logins, rejects, deliveries and queue-id correlation against the smtplib, imaplib and poplib script; classic and ISO syslog layouts; `dovecot.log` | Counts equal; the SASL user and client address of a delivery come from the earlier `client=` line; the guest's `maillog`: 2 of 2 |
| `postgres-log` | PostgreSQL 15.19 | The same session in `stderr` (Debian prefix and the upstream one), `csvlog` and `jsonlog`: 88 and 76 entries per format, 11 logins, 5 failed logins, statements, multi-line statements | The three formats agree entry for entry once DETAIL/STATEMENT lines are folded; the `PASSWORD '...'` literal the server logs in clear is replaced |
| `mysql-error-log`, `mysql-general-log`, `mysql-slow-log` | MariaDB 10.11.19, MySQL 8.4.13 | Connect, denied and statement entries against the clients' script; slow-log blocks against `# User@Host:` lines | Equal; MariaDB writes `IDENTIFIED BY 'secret'` in clear, which is replaced |
| `haproxy-log` | HAProxy 2.6 through rsyslog | 10 requests (HTTP, a 503 after a connect timeout, TCP) | Equal; timers, termination state, status, bytes |
| `squid-access-log`, `squid-cache-log` | Squid 5.7 | 7 proxied requests in the native and the combined log | Equal; results, statuses, elapsed time |
| `named-query-log` | BIND 9.18 | 8 `dig` queries (A, AAAA, MX, TXT over TCP, NXDOMAIN, PTR, no recursion, ANY) | Equal, flags included |
| `fail2ban-log` | fail2ban 1.0.2 with real sshd failures | Found, Ban, already banned and Unban lines | Equal |
| `dhcpd-leases`, `dhclient-leases` | ISC dhcpd 4.4.3 answering dhclient 4.4.3 | The lease, the client's expiry arithmetic | Equal |
| `vsftpd-log`, `xferlog` | vsftpd 3.0.3 (`dual_log_enable`) with ftplib | Connections, logins, failed logins, uploads, downloads, deletes | Equal |
| `samba-log`, `samba-audit` | Samba 4.17.12 with `full_audit` and smbclient | Logins (good, wrong password, unknown user) and 35 audited operations | Equal |
| `modsec-audit-log` | Apache 2.4 with ModSecurity 2.9.7 and OWASP CRS 3.3.4 | 7 transactions, 4 blocked, the rule ids and messages of each | Equal |
| `tomcat-log`, `web-access-log` (Tomcat, CUPS paths) | Tomcat 10.1, CUPS 2.4 | Every line of `catalina.out`, the juli logs and both access logs | Equal |
| `gtk-recent-files`, `trash`, `thumbnails` | GTK 3 with real gedit and eog, `gio trash`, libgnome-desktop's thumbnail factory | 4 recent entries with their applications and counts, 4 trash records (a purged file, a directory, a `%20` name), 2 thumbnails and a failed one against the session script's own times | Equal |
| `cups-page-log`, `cups-jobs` | CUPS 2.4.2 with a deskjet queue | 3 jobs by 2 users: titles, users, page totals, creation times | Equal |
| `chromium-downloads`, `chromium-cookies`, `chromium-extension-settings` | Chromium 156 (headless, DevTools protocol) | One real download (state, danger type, bytes, tab URL, MIME, start and end), two cookies, a `--load-extension` extension in `Preferences` | Equal to `sqlite3` and the JSON file |
| `firefox-cookies`, `firefox-extensions`, `firefox-prefs`, `firefox-session` | Firefox ESR 153.7 (headless) | Two cookies (in the WAL), the profile's ten built-in add-ons, the proxy and DNS-over-HTTPS prefs, the session file's two tabs | Equal. `expiry` is in milliseconds in this version (older profiles: seconds); the reader tells the unit by size |

Also run on ten real virtual machine disks (CentOS 7 and 10, Rocky 8 and 9, AlmaLinux 9, Debian
12 and 13, openSUSE Leap, Alpine, Arch): about 4,400 tasks, none failed. The CentOS 7 guest's
`maillog` (1 delivery) and the installer logs of two guests with 4 and 1 USB root hubs are read
as `grep` counts them. No guest has a real USB device or a desktop session.

Mutation (thousands of byte flips and every truncation of each fixture) and a 60 s fuzz run
cover the binary readers: the PNG chunk walker (`thumbnails`), the IPP reader (`cups-jobs`),
and the `mozlz4` reader (`firefox-session`). The credential tests plant a secret in each
artifact that sits near one (SQL `PASSWORD` clauses, Remmina and FileZilla passwords, Chromium
`password_value`, Firefox `encryptedPassword`, ModSecurity `Authorization` and `Cookie`
headers and bodies) and assert it never reaches a record or the timeline.

Synthetic only, from the vendor's format description: Remmina `.remmina` profiles and
FileZilla `recentservers.xml` and `sitemanager.xml` (the GUI creates them); Firefox
`logins.json`; the rows of Chromium's `Login Data` (the real schema, with rows inserted by
`sqlite3`, because the browser saves a login only through its UI); Exim `A=` and
`authenticator failed` lines (the Debian package did not advertise AUTH in the container);
`usb-devices` for a mass-storage disk and a keyboard (the line layouts are the kernel's, the
root hubs and the tablet of the guests are real, the rest is written by hand).

Statement logs (`postgres-log`, `mysql-general-log`, `mysql-slow-log`) are shown as the server
wrote them, except that the literal after `PASSWORD` or `IDENTIFIED BY` is replaced. A secret
an application sends in an ordinary `INSERT` or in bind parameters is not recognisable and is
shown. `mail-log` is stateful and reads 346 MiB/s of input per core, CSV output included; the proxy,
FTP and database parsers run at 128 to 244 MiB/s per core with the output included (their
output is as large as their input), below the 300 MiB/s text target. See `docs/PERFORMANCE.md`.

## macOS stores read from documentation only

These macOS artifacts were written from published format descriptions and open-source parsers
(named in each module's comment) and tested on fixtures built by `test_files/*/generate.py`
from the same descriptions. No real file of these kinds was read, so they are **Synthetic
only**, and a parser may be wrong where the description is. Where a layer could be checked
against Apple's own code, that is said below.

| Artifact | Specific doubt |
|---|---|
| `powerlog` | Table and column names differ between macOS versions: tables are matched by lowercase prefix (`PLApplicationAgent_`, `PLAppTimeService_`, `PLProcessNetworkAgent_`, `PLSleepWakeAgent_`, `PLDisplayAgent_`, `PLBatteryAgent_`, `PLWifiAgent_`, `PLBluetoothAgent_`, camera and audio agents) and every column is kept in `detail`. `time` is `timestamp` plus the `system` value of the nearest earlier `PLStorageOperator_EventForward_TimeOffset` row (the rule of the APOLLO project); its sign and meaning were not verified, and `raw_time` always keeps the stored value |
| `crash-reports` | `.ips` key names are those of macOS 12 to 14 samples in public write-ups; the text `.crash`, `.hang`, `.spin`, `.diag`, `.shutdownStall` and `.panic` headers are read as `Key: value` lines. Only header and summary fields and at most eight frame names of the faulting thread are kept; the thread dump is never copied. Old Intel `.panic` files carry no date in the header read here |
| `rosetta-aot` | Records the file, its SHA-256, Mach-O header, UUID, segment names and file time. **The path of the original x86_64 binary is not recovered**: no reliable path field is known in the cache file, and the file name is a hash. The time is the file's modification time as collected, not a recorded instant |
| `netusage`, `dhcp-leases`, `network-interfaces` | Core Data column names follow the APOLLO `netusage` module; lease keys (`IPAddress`, `LeaseStartDate`, `RouterHardwareAddress`, `SSID`) follow public research |
| `url-cache` | The archived `response_object` and `request_object` are searched, within a bound, for a fixed list of HTTP header names (`Set-Cookie`, `Cookie` and `Authorization` are never copied) because their exact layout was not verified. Bodies are never output, only their size. `time_stamp` is taken as UTC text |
| `binary-cookies` | Cookie VALUES are never read; the record layout (offsets, flag bits 1 secure and 4 HttpOnly, two Mac-time doubles) follows public descriptions |
| `hsts` | Layout of `HSTS.plist` follows public descriptions |
| `shared-file-lists` | The keyed-archive layer and the bookmark layer were checked against data written by Foundation for a file the checker created: path, volume name, volume UUID, volume size, volume and file creation dates equal what Foundation reports. The `.sfl2`/`.sfl3` item keys (`Name`, `Bookmark`, `uuid`, `visibility`) were not checked on a real list. Legacy `Alias` records (before OS X 10.10) are not decoded. The bookmark keys for file id and creating user were not found in Foundation's own output and may be absent on current systems |
| `ds-store` | The buddy-allocator and B-tree layer reads the public `Test_DS_Store` sample of the `ds_store` project (MIT licence), the same 3 of 3 records as that project's reader. Other record types and deeper trees are synthetic only. Blob values (view settings) are only counted. `dutc` dates are read as fixed-point seconds since 1904 |
| `finder-prefs`, `dock-items`, `login-window`, `spotlight-shortcuts` | Key names follow public descriptions of the preference domains; the Spotlight shortcut file name and layout (`LAST_USED`, `DISPLAY_NAME`, `URL`) differ between releases |
| `auth-db` | `class` numbering (1 user, 2 rule, 3 mechanisms, 4 allow, 5 deny) follows Apple's open-source Security framework. `authdb_rule_changed` events are written only when a rule's `modified` is more than a day after `created` (rules are created together at install) |
| `exec-policy` | The time columns are taken as Unix seconds and dropped, with a warning, when they are not plausible as such; the real epoch was not verified. Column names are read from the schema |
| `pkg-receipts`, `config-profiles`, `application-firewall`, `bluetooth-devices`, `time-machine` | Key names follow `pkgutil`, Apple's profile key reference and public descriptions of the `defaults` domains. Profile payload content (certificates, passwords) is never output, only payload types |
| `lockdown-pairings` | Only `HostID`, `SystemBUID`, `WiFiMACAddress` and the file time are read. Private keys, certificates and escrow bags are never read; the tests plant them and check that none appears |
| `startup-items`, `legacy-rc`, `folder-action-scripts`, `system-plugins` | File presence and metadata (and, for rc files, the command lines) are the evidence |
| `messages`, `mail-envelopes`, `call-history` | **Content decision.** Like the shell and Safari history artifacts, Messages records include the message text; it is the single field `text`, switched by the constant `INCLUDE_MESSAGE_TEXT` in `communications.rs`. Rich text kept only in `attributedBody` is not decoded, so `text` is empty for those messages. Mail records never include a body. Mail's schema varies by `V<n>` folder; call types 1, 8 and 16 follow public descriptions |

Time-offset, epoch and layout doubts above are the reason these were not claimed as verified.

## Package records

The package artifacts for Arch, Alpine, SUSE, Gentoo, Void, Photon and the older yum systems
read what each package manager keeps. They differ in what they know, and a few facts are easy
to misread:

- **No install log on Alpine.** apk keeps no history and no install time. `apk-installed`
  has the package's build time, its `world` membership (`explicitly_installed`) and the owned
  file count, and no timeline events. `apk-world` lists what was asked for by name.
- **Install times from file times.** Gentoo (`portage-db`) and yum (`yumdb`) store no
  install time. `time` there is the modification time of the package's database files, which
  portage and yum write at install: it matches the logged install within seconds on the test
  hosts, but it is file metadata, not something the package manager recorded, and a copy
  that did not keep file times (a plain `cp -r`) loses it. Gentoo's `build_time` is when the
  package was built (a binary package is much older than its install).
- **Minute precision.** xbps writes `install-date` to the minute, and the older `pacman.log`
  form (`[2019-01-02 03:04]`) has no seconds. The seconds are 0.
- **Zones.** zypper history, `alternatives.log` and old-form `pacman.log` times have no zone and
  are marked `assumed_zone`. Current `pacman.log`, `emerge.log` (epoch), xbps (`UTC`), tdnf and
  yum (epoch) are recorded in UTC.
- **One task for a database of many files.** `pacman-db`, `portage-db` and `yumdb` read a
  directory of one small file per package (a thousand or ten thousand of them). A task per file
  would be that many tasks and output files, so each artifact is triggered by one file that
  every such host has (`var/lib/pacman/local/ALPM_DB_VERSION`; for Gentoo the first of
  `var/cache/edb/counter`, `var/lib/portage/world` and `var/log/emerge.log`; `var/lib/yum/uuid`)
  and walks the packages itself. `source_path` in these records is that file; the record's own
  `package_path` (pacman) or `package` names the package. A host with the packages but none of
  those files gets no records from them, and a collection that holds only the per-package files
  (a UAC collection does not, by default) needs one of them added.
- **zypper history** skips libzypp's `#` comment lines (per-package success lines and rpm
  script output). `patch` lines are records without events.
- **ndb.** Packages that were removed leave stale blobs in the file; they have no slot and are
  not recovered. A blob whose Adler-32 checksum does not match is a warning and is not read.
- **yum history** in rollback-journal mode: an unfinished transaction in the `-journal` file is
  not applied. `login_user` comes from the host's `/etc/passwd` and is empty when the uid is
  absent (a script or a daemon) or unknown. `yumdb` lists only what yum installed: packages put
  on the image by another tool (kickstart, an image builder) are in the rpm database but not
  in yumdb, and an entry whose package was later removed with `rpm -e` stays in yumdb.

Checked on twelve scripted container collections and four VMs (the figures are in the "Real
tool" row above): counts, names and versions equal the package manager's own list, and the
scripted installs and removals appear at the logged seconds. `yumdb` is by design a subset of
`rpm -qa`: on CentOS 7 it has 169 entries against 168 packages, the extra being a stale
`kernel` entry whose package had been removed with `rpm -e`. `tdnf-history` and
`alternatives-log` were checked only on files made in throwaway containers (the tdnf
transactions equal `tdnf history list`); no Photon or Debian collection had them.

## FreeBSD, OpenBSD, NetBSD and BSM audit trails

A BSD host is found by its files (`etc/freebsd-update.conf`; `etc/installurl` or `etc/examples`;
`etc/release` with `etc/rc.d`) or, failing that, by the name of a UAC collection. Its name and
release come from `rc.conf`, `etc/myname`, the `freebsd-update` tag, `etc/release`, a UAC
`uname -a` or the first line of `etc/motd`. A BSD host is read from a collection, a plain tar of
the root, a mounted folder or a disk image (UFS/FFS, and ZFS on FreeBSD). A Linux system that also
has `etc/release` and `etc/rc.d` (Mageia) is told apart by its `os-release` or by the name of its
UAC collection.

What is read:

| Area | FreeBSD | OpenBSD | NetBSD |
|---|---|---|---|
| Logins | `utx` (`utx.log`, `utx.lastlogin`, `utx.active`) | `bsd-utmp` (`wtmp`, `utmp`), `bsd-lastlog` | `bsd-utmp`, `bsd-lastlog`, `netbsd-utmpx` (`wtmpx`, `utmpx`) |
| Audit | `bsm-audit` (`var/audit/*`) | | |
| Packages | `pkg-db` (`local.sqlite`), `pkg-log` (`pkg[N]:` lines of `messages`) | `pkg-add-db` (`var/db/pkg/*/+CONTENTS`) | `pkgsrc-db` (`usr/pkg/pkgdb`), `pkgin-db` |
| Logs | `auth.log`, `messages`, `security`, `cron`, `daemon.log`, `devd.log`, `userlog`, `xferlog`, `dmesg.today`, `setuid.today`... | `authlog`, `secure`, `messages`, `daemon`, `xferlog`, `daily.out` | `authlog`, `secure`, `messages`, `xferlog` |
| Accounts | `master-passwd` (hash type only), `passwd`, `group`, `sudoers`, `doas-conf`, `login-conf` | the same | the same |
| Persistence | `rc-conf`, `rc-d`, `bsd-rc-local`, `loader-conf`, `ttys`, `devd-conf`, `jail-conf`, `cron`, `cron-scripts` (`periodic`, `daily.local`), `bsd-at-jobs`, `shell-profiles` (`.profile`, `.cshrc`, `.shrc`, `.login`), `authorized_keys` | the same (no `loader-conf`, `devd`, `jail`) | the same |

`pflog` is a pcap file and is not read. FreeBSD's `pw` writes account changes to `userlog`, not to `auth.log`;
OpenBSD and NetBSD `useradd`, `usermod`, `userdel`, `groupadd` and `groupdel` write `new user added: name=...` lines
to `messages`, which `auth-log` classifies (`account_created`, `account_modified`, `account_deleted`, `group_created`,
`group_deleted`). `sudo -n` by a user the rules refuse leaves no line on FreeBSD (`doas` does: `failed command for`
on FreeBSD and NetBSD, `command not permitted for` on OpenBSD). BSD `syslogd` writes `last message repeated N times` for
identical consecutive lines: those summaries are records without an event, and the lines they stand for are not expanded.

Details to know:

- **Time of an install.** FreeBSD's `pkg` records it (`packages.time`). OpenBSD's packing list and
  pkgsrc's database do not: the record's `time` is the modification time of `+CONTENTS` as the
  collection kept it, and `time_source` says `file mtime`. pkgin's `pkgin.db` has the build date only.
- **Anchored package databases.** `pkg-add-db` is triggered by `var/db/pkg/quirks-*/+CONTENTS` (the package
  `pkg_add` installs first) and `pkgsrc-db` by `pkgdb.byfile.db`, and each walks the packages itself (as
  `pacman-db` does). A database without them gets no records. pkgsrc's `pkgdb.byfile.db` and NetBSD's
  `lastlogx`, both Berkeley DB 1.85 hash files, are not read.
- **`audit_user_id` 4294967295** in a BSM record means the process had no audit user (`-1`).
  Events are named from the host's operating system (FreeBSD and macOS tables are shipped; a host
  of another system gets numbers and one warning, because Solaris numbers events differently).
  A record with a token this parser does not know is kept up to that token and one warning per run
  counts them (`token id 0x.. is not understood`); the next record is read from its length. A time
  field that is not a plausible date is left empty and warned about.
- **FreeBSD `utx.log`** has no marker between records: a bad length stops the file with one warning.
- **OpenBSD `at` jobs** are named `<run time in epoch seconds>.<queue>` and have no job number (`job_number` is empty); FreeBSD's are named like Linux's.
- **Compressed collections and hard links.** In a `.tar.gz` a file is read only if some artifact names it. FreeBSD's `/root/.profile` and `/root/.cshrc` are hard links to `/.profile` and `/.cshrc`, so `shell-profiles` also lists those two (otherwise the links could not be read).
- **Persistence checks** do not judge comment-only plants (an `rc.securelevel` or `csh.cshrc` holding
  only `# NXMK_...`), a restricted `doas` rule (`cmd` given), or a planted key of an ordinary user.
- **Not read** (collected by UAC or present in the plain tars and ranked by what they could hide):
  `etc/mail/aliases` and `etc/aliases` (`|command` destinations), `etc/inetd.conf`, `etc/pam.d/*`,
  `etc/syslog.conf` (`|command` destinations), `etc/hosts.equiv` and `.rhosts`, `etc/periodic.conf`,
  `etc/newsyslog.conf`, `etc/ssh/ssh_host_*` and moduli, `var/db/freebsd-update/*` (its `tag` file is used
  for the release), `.mailrc`, `.login_conf`, `.history` and `.sh_history`, and
  `boot/modules/*` (listed only by the body file).

Checked against (FreeBSD 14.5 on UFS and 14.4 on ZFS from the official `BASIC-CLOUDINIT` images, NetBSD
10.1 from the official live image, OpenBSD 7.8 from the official installer; a scripted run across a
reboot on each, collected with UAC 3.4.0 `ir_triage` and as a plain tar of `/etc /var/log /var/db
/var/audit /var/cron /root /home`, both read; the guests' own tools as the reference):

| Reference | Result |
|---|---|
| `getutxent()` dump of `utx.log`, `utx.lastlogin`, `utx.active` | `utx.log` 51, `utx.lastlogin` 2 and `utx.active` 3 records on each of the two guests: type, time to the microsecond, id, pid, user, line and host equal, 0 mismatches. The same files read from the UAC collection (`utx.log`, `utx.lastlogin`): equal |
| `last(1)` boot and login sessions | 3 boot records and 24 login sessions on each guest: equal to the records |
| `praudit -r` and `praudit -l` of every record of the guests' audit trails | 4,282 records (2,140 on UFS, 2,142 on ZFS; 6 trails), every header, subject, return, path, text, argument, exec argument and environment, attribute and socket field, and the event name: 0 mismatches. The tokens in these trails: header32, subject32 and subject32_ex, return32, text, path, arg32, attr32, exec_args, exec_env, exit, socket-unix, trailer |
| `pkg query '%n %v %t'` | 10 of 10 packages and install times on each guest; the scripted `zip` removal in `messages` |
| The four guests' disk images, UAC collections and plain tars (12 inputs) | Each is one host with the right system and release, no failed task and no warning. FreeBSD 14.5 on UFS2 and 14.4 on ZFS; NetBSD 10.1 on an FFSv1 that the guest had grown (its size is only in the superblock's 64-bit field, and its disklabel partition reaches past the MBR entry around it, which keeps the old size); OpenBSD 7.8 with `/`, `/usr` and `/home` in one disklabel, joined into one host through the `<disk id>.<letter>` names of its `fstab`. The NetBSD and OpenBSD volumes were not compared file by file with a mount |
| `crontab -l`, `sysrc -a`, `service -e`, `passwd` | every cron entry, every `*_enable` variable and every account equal |
| the script | every scripted login, failed login, `sudo`, `doas`, `su`, account change and package event found; see the table in the report of the run |
| NetBSD 10.1: `fread()` of the libc `struct utmp`, `struct utmpx`, `struct lastlog`; `pkg_info`, `pkgin list` | `wtmp` 32 of 32 records, `utmp` 3 of 3, `lastlog` 3 of 3, `utmpx` 6 of 6, and a copy of `wtmpx` 35 of 35 (type, time to the microsecond, name, line, host); `pkg_info`: 8 of 8 packages from `pkgdb` and 8 of 8 from `pkgin.db`; every scripted failed login, `doas` refusal, `su` and BSD `login` line classified |
| OpenBSD 7.8: `fread()` of the libc `struct utmp` and `struct lastlog`, `last(1)`, `pkg_info -a` | `wtmp` 40 of 40 records, `utmp` 1 of 1, `lastlog` 3 of 3 uids; `last(1)` 17 of 17 sessions; `pkg_info -a` 9 of 9 packages (`quirks` anchor); every scripted failed login, `su` and `login` line, the `doas` refusal and the first `doas` run (`syslogd` folds the identical others into `last message repeated N times`, which is written later and is not expanded), and every `useradd`/`usermod`/`userdel`/`groupadd`/`groupdel` line of `messages` |

### Synthetic only

- **BSM written by macOS.** A macOS trail needs root to produce. macOS is read by the same parser, with
  macOS's own event table, and tested only with `test_files/bsm-audit/macos-synthetic.audit`, built by
  `make_synthetic.py` from audit.log(5) and OpenBSM's `audit_record.h`. Doubts: the subject token macOS
  writes for local logins (`subject32_ex` with an IPv6 address, a 64-bit port), and `AUE_` events newer
  than the table.
- **BSM tokens no FreeBSD amd64 trail contained.** `header64`, `header32_ex`, `header64_ex`, `subject64`,
  `subject64_ex`, `process*`, `return64`, `arg64`, `attr64`, `socket` (`0x2e`), `socket_ex`,
  `socket-inet` and `socket-inet6`, `in_addr`, `in_addr_ex`, `ip`, `iport`, `seq`, `zonename`, `groups`,
  `cmd`, `ipc`, `ipc_perm`, `opaque`: layouts from audit.log(5) and `audit_record.h`, in
  `tokens-synthetic.audit`. Solaris and illumos trails are a real check of their own (see "Solaris
  and illumos").
- **Big-endian BSD hosts.** The byte order of OpenBSD and NetBSD `utmp`/`wtmp`/`lastlog`/`utmpx` is
  detected by which makes the times plausible; only little-endian amd64 files were seen.
- **FreeBSD `utx` records of other types** (init and login processes, shutdown, clock changes): the
  layout is the same, but only boot, user and dead records occurred.

## Solaris and illumos

Hosts are recognised by `etc/svc`, `var/svc` or `lib/svc`, or by `-solaris-` in a UAC collection's name.
The host name is `etc/nodename`, the version is `etc/os-release` (illumos distributions) or the first line
of `etc/release`, and the zone is the `TZ=` of `etc/default/init`.

**What was verified, and what was not.** A free illumos distribution stands in for the systems that need a vendor
login. Two OmniOS guests (r151054 and r151060, x86, KVM) ran a script: users, a role, ssh key and password logins,
`su`, `sudo`, `pfexec`, `passwd`, `pkg install` and `uninstall`, a real `pkgadd` of a package built with `pkgmk`, cron and
`at` jobs, a reboot, and 29 persistence examples (SMF services and manifests, `inetconv`, `rc` scripts, `inittab`,
profiles, `crle`, `/etc/system`, a driver `.conf`, RBAC profiles, PAM, `.rhosts`). Each guest was read as a UAC 3.4.0
`ir_triage` collection (UAC has no Solaris profile; its Solaris artifacts are in `ir_triage`) and as a `tar` of the
evidence directories, and compared with the guest's own tools.

| Parser | Compared with | Result |
|---|---|---|
| `wtmpx`, `utmpx` | `fwtmp` on the same bytes; `last` | 38 and 7 records on each guest, 540 fields each, 0 differences; 7 logins and 2 boots as `last` shows |
| `solaris-lastlog` (`lastlog.v2`) | the `Last login:` line sshd prints from the file | both users on both guests: time and host equal |
| `sulog`, `loginlog`, `cron-log` | the files line by line | 16 `sulog` and 5 `loginlog` lines on each guest, 14 and 12 `cron-log` lines, all equal (month, day, time, flag, tty and users; each cron end line gets its start line's command, and the `rc=` codes equal) |
| `smf-repository` | the repository's own `sqlite` shell, `svcs -a`, `svcprop` | every row of every table (about 40,000 rows per repository, two repositories and two small ones) identical; 156 of 156 instances, enabled state and start, stop and refresh methods equal |
| `smf-logs`, `smf-manifests` | the files; `svcprop` of the imported services | methods and enabled flags equal |
| `ips-history`, `ips-packages` | `pkg history -l`, `pkg list -H` | 17 and 16 of 17 and 16 operations (operation, times, user, command), 424 and 420 of 424 and 420 packages (r151060 keeps them in an SQLite `catalog.db`), equal |
| `svr4-pkginfo`, `svr4-contents` | `pkginfo`, `pkginfo -l`, `pkgchk -l` | 219 of 219 packages; the package built here equal in every field |
| `user-attr`, `rbac-profiles`, `solaris-shadow`, `solaris-at-jobs`, `crle-config` | `profiles`, `roles`, `atq`, `crle` | equal for the accounts, the job and both configuration files |
| `persistence-hunter` | the 28 examples that were still in the evidence (one more, a user crontab, was removed by the script) | 24 flagged on each guest, as a `tar` and as a UAC collection; 25 when the whole `kernel/drv` tree is collected (UAC does not collect it, and a driver `.conf` is judged only against a module tree). Not flagged: the `prof_attr.d` fragment of the added profile (the `exec_attr` entry that uses it is flagged), `/etc/project` and `/etc/services` (no check) |

**What was not verified.** Oracle Solaris 10 and 11 were not available (a vendor login is needed to download them). From
documentation only: Solaris 10 without IPS (no `ips-*` records; `svr4-*` from `var/sadm` are read), the
patch fields of SVR4 `pkginfo`, Trusted Extensions label attributes (kept as text), the `/etc/system.d` and `/etc/user_attr.d`
fragments of Solaris 11, SPARC (big-endian) files, the old 28-byte `lastlog`, and the SMF repository of any Solaris 10 or 11 system
(a repository that is an SQLite 3 file is refused with an error that says so). The big-endian forms of `wtmpx`, `lastlog` and the SQLite 2 reader are
tested on files converted from the little-endian ones, not on a SPARC host.

BSM audit trails (`bsm-audit`, `var/audit/*`) were compared with `praudit -r` on the two OmniOS guests: 342,552 records in four trails
(token version 2: nanosecond times, no trailer token, event names from the host's own `etc/security/audit_event`), and the event, time,
process id, paths, text, privileges used (`use of privilege`), authorizations, service names (FMRI) and user tokens of every record are equal.
Two values are shown differently from `praudit`: a 64-bit return value is shown whole, where `praudit` prints its low 32 bits (they differ
only for `AUE_AUDITON_GETCOND`, whose upper half is not zero), and a return status of -1 is shown as 255; a 32-bit return value of -1 is shown
as 4294967295. A Solaris host found only by a bare copy of `var/audit` needs `etc/svc`, `var/svc` or `lib/svc` beside it to be recognised.

What is not read: process accounting
(`pacct`; `acct` lives in another parser), the old 36-byte `wtmp` and `utmp`, `etc/svc/volatile` (the non-persistent SMF repository:
a service's state and temporary `svcadm enable -t` changes; `smf-repository` reports `enabled` as the persistent setting, so a service
that is disabled for the moment shows enabled, as one did in the check), the `crle` tables of alternative objects and `.sh_history`. `sudo` logged nothing to syslog on OmniOS, so a sudo command is in the audit trail only.
OmniOS logs no `auth` messages by default: a collection from such a host may have no ssh or `su` lines at all.

A few facts that are easy to misread:

- **The SMF repository is SQLite 2.1**, not SQLite 3, so it is read by a reader of its own (`solaris/sqlite2.rs`) and not by the `sqlite`
  helper. It has no import time and no run-time state. The `repository-boot*` and `repository-manifest_import*` backups in `etc/svc` are read as
  further repositories (their names give the time they were made).
- **Legacy services.** `svcs -a` lists `lrc:` entries for the scripts in `etc/rc?.d`; they are not in the repository (`rc-scripts` reads the scripts).
- **Properties** of an instance are read as `svcprop` shows them (the `running` snapshot, an instance's group before its service's);
  `enabled` is read from the current groups, as `svcs -l` shows it.
- **No year** in `sulog`, SMF logs and the cron log lines of the restarter: years are inferred from the file's time, as for classic syslog.
  The `var/cron/log` and `loginlog` times have a year and no zone (`assumed_zone`).
- **`inetd` services** have no `start` method: `start_exec` holds the `inetd_start` command, which inetd runs for each connection.

## IBM AIX

No AIX system, collection or file was available (AIX needs IBM hardware and an entitlement), so
this support was written from documentation and from public source code and samples. Each
artifact is in one of three states: **(a)** checked against a real public sample, **(b)** layout
confirmed by two independent sources, fixtures synthetic, **(c)** one source, fixtures synthetic,
kept conservative (a record that does not fit is a warning). Nothing below was run against a real
AIX file except the two samples named in (a).

| Artifact | State | Sources and the doubt |
|---|---|---|
| `aix-wtmp`, `aix-utmp`, `aix-failedlogin` (`struct utmp`, 648 bytes, big-endian) | (b) | A copy of AIX's `utmp.h` in a public repository and the `libc` crate's AIX bindings give the same declaration; the offsets are computed from it by `test_files/aix-utmp/make_fixtures.py`. Kaitai Struct's `aix_utmp.ksy` agrees on the size and on the time, exit and host offsets but puts the type at offset 342 instead of 340; a file shaped that way is refused, not guessed. The 32-bit and 64-bit builds write the same bytes (a spare word before the 32-bit time); an unset spare word is a warning. The `ut_type` of a `failedlogin` record is unverified, so every non-empty record there is a failed login |
| `aix-lastlog` | (a) for the shape | Two public excerpts of `etc/security/lastlog` (a magazine article and a blog post with real output: 2 stanzas, 14 attributes, all read, dates plausible for each source's year). Written against nothing else |
| `aix-errpt`, summary listing | (a) | Three public `errpt` listings in a Ruby parser's test data: 51 rows, 51 read, no warning |
| `aix-errpt`, `errpt -a` blocks | (c) | IBM's description of the command; no sample |
| `aix-lslpp` | (b) | `lslpp -hc` (`Path:Fileset:Level:PTF Id:Action:Status:Date:Time`, time printed with `;`) and `-Lc` field orders from Microsoft's Operations Manager agent source, and `lslpp -lc` from IBM's `ansible-power-aix` for the listing form; no real output, so the history `Date` and the listing's `State` and `Fix State` columns are the least certain |
| `aix-security-passwd`, `-user`, `-group`, `-config` | (b) | Stanza shape from the two `lastlog` excerpts, the L0phtCrack AIX importer (also the hash prefixes `{smd5}`, `{ssha1}`, `{ssha256}`, `{ssha512}`, a 13-character DES hash, `*`, the `lastupdate` epoch, the `ADMCHG` flag and the `MMDDhhmmyy` `expires`) and SaltStack's `aix_shadow`. IBM's pages were not reachable. Hashes are never output |
| `aix-sulog` | (c) | The SVR4 line (`SU 03/10 01:02 + pts/1 alice-root`) from illumos's `sulog(5)`. The user pair is split at the last `-`, so a target user whose name has a dash is split wrongly. Year inferred from the file's modification time |
| `aix-cron-log` | (c) | The System V cron log shape as remembered (`!` daemon, `>` start with a `CMD:` line before it, `<` end); no source was fetched |
| `aix-inittab`, `aix-inetd-conf`, `aix-rhosts`, `aix-rc-scripts` | (c) | Fetched illumos manual pages `inittab(5)`, `inetd.conf(5)` and `hosts.equiv(5)` (System V relatives; AIX's own pages were not reachable); AIX's comment markers (`:` and `#`) are as remembered. No list of AIX's stock `inittab` entries is built in, so `aix-inittab-nonsystem-command` only means the program is outside `/etc`, `/usr`, `/sbin`, `/bin`, `/opt`, `/lib` and `/var/opt` |
| `aix-at-jobs` | (c) | Job files named `<epoch>.<queue letter>` as remembered; the command is assumed to be the last lines of the script, after the saved environment. The Linux `at-jobs` parser does not apply |
| `aix-sh-history` | (c) | ksh93's `history.c` documents the layout (header `0x81 version`, NUL-terminated commands on even bytes, `0x81 0x00` cancel, six-byte `0x82` number marker). AIX's own `ksh` is ksh88 and was assumed to match; a file without the header is read as lines |
| `aix-smit` | (c) | No format source: lines are kept as written with no times and no fields |
| `aix-audit-stream` | (c) | The `event login status time command` columns named in the task; no sample. The binary `audit/trail` is not read |
| `aix-alog-output` | (c) | `alog -o -t <type>` output kept line by line; the raw alog files are not read |
| `aix-live-network` (`netstat -an`, `-Aan`), `aix-live-rmsock`, `aix-lssrc`, `aix-genkex` | (c) | Documented output of the commands; no real output. `rmsock` is read for the message `... is being held by proccess N (name)` |
| `aix-rpm-db` | (c) | The existing `rpm-db` reader (which does read big-endian Berkeley DB, checked on an s390x image) pointed at the Toolbox's database paths, which are as remembered and unconfirmed |
| Host name, `oslevel`, zone | (c) | Name from a saved `hostname`, `uname -n`, `uname -a` or `lsattr -El inet0`; level from `oslevel -s`, `-r` or plain; zone from `TZ=` in `etc/environment` (Olson name or POSIX string). UAC saves only `uname -L` and `oslevel`, so a plain UAC collection is named after its folder |

What is read and what is not, for an AIX host: login records (`var/adm/wtmp*`, `etc/utmp`,
`etc/security/failedlogin`), the `etc/security` stanza files above, `etc/passwd` and `etc/group`
(a `!` in the password field means the hash is in `etc/security/passwd`), syslog files under
`var/adm`, crontabs (`var/spool/cron/crontabs`) and at jobs (`aix-at-jobs`), `.profile` and `.kshrc`, and the
UAC command output of `errpt -a`, `lslpp`, `netstat`, `ps`, `lssrc`, `genkex`, `alog` and `rmsock`.
Not read, and named when met: the raw error log `var/adm/ras/errlog`, the circular alog files
(`conslog`, `bootlog`, `bosinstlog`, `nimlog`), the ODM classes in `etc/objrepos` (`SRCsubsys`,
`history`, `product`), `audit/trail`, and `etc/security/tsd`. Their layouts could not be
established from two independent public sources; the command output that carries the same
information (`errpt`, `alog -o`, `lslpp`, `lssrc`) is read instead where a collector saved it. The
AIX 4.1.3 source code that circulates in public repositories was deliberately not consulted.

## Not supported

| Area | What | What happens |
|---|---|---|
| Packages | BerkeleyDB rpm databases in btree format | Skipped, naming the format |
| Packages | Photon's `tdnf.log`, `var/log/apt/term.log` (free-form terminal output: the sessions are in `apt-history` with the same times), the Alpine, Void and Arch package managers' own caches | Not parsed |
| Docker | Image layers and image configuration in the containerd image store (Docker 29 default) | `containerd-images` reads the image names, digests, manifest sizes, labels and the time containerd recorded each image from `io.containerd.metadata.v1.bolt/meta.db`; when an image was built, its layers and its history are in content blobs that are not read. Containers and logs still parse; `containerd-containers` reads the container and sandbox records of the same file (see the Kubernetes rows below) |
| Kernel ring buffer | Seconds since boot (`[    7.58]`) as clock times | `dmesg` keeps them as `monotonic_seconds`; only `dmesg -T` output (a wall-clock time with no zone) gets a timestamp, in the assumed zone. The file does not hold the boot time |
| Docker, Podman | Data roots found by a configured path alone | The artifacts match the layout below the root (`containers/<id>/`, `image/<driver>/`, `<driver>-containers/`) under any prefix, so a root moved with `data-root`, `--root` or `graphroot` is found without reading the configuration. A tree that merely looks like it (a container's own copy of `/var/lib/docker`) is read as well, and shows its path in `source_path` |
| systemd | `Alias=` and `Also=` inside unit files, `.target` units, and links under `usr/lib` and `lib` (vendor presets, not enablement) | Not read. Links in `etc/` and home directories (`*.wants/`, `*.requires/`, `*.upholds/`, aliases, masks to `/dev/null` or an empty file, `var/lib/systemd/linger/*`) are read by `systemd-enablement`; `persistence-hunter` joins them and the timer-to-service relation to the unit records |
| Persistence | Git hooks, `etc/network/if-up.d`, apt hooks, `dhclient-exit-hooks.d`, `Xsession.d`, upstart jobs, `AuthorizedKeysFile`, generators under `usr/lib`, `modprobe.d` `remove` directives | Not read or not judged. See "Not detected" in `docs/PERSISTENCE_HUNTER.md` |
| Unified Log | Backtraces; signpost names; state dumps that are not property lists; a few Apple-private value decoders. About 0.1% of log messages and 12% of state dumps differ from `log show` | The entry is kept; the message shows the raw value or a size marker |
| Unified Log | Oversize message data stored in a file other than the entry's own or its neighbour | The message shows `<oversize data in another file>` |
| Unified Log | `log show` leaves out whole files it considers expired (about 15% of the entries in the test archive). The rule it uses was not established | nixcavate outputs every entry that is in the files, so its counts are higher than `log show`'s |
| Disk images | F2FS, NTFS, LUKS, Fusion and multi-device APFS, EWF2 (`.Ex01`) | The partition is named in a warning and skipped |
| Btrfs | Data on another device of a multi-device filesystem, and block groups with the RAID0, RAID10, RAID5 or RAID6 profile (single, DUP and the RAID1 family are read from the copy on the device in the image) | One warning names them; files stored there are listed but not read |
| Btrfs | Checksum verification, log tree replay (writes synced since the last commit), encrypted extents, extended attributes, send streams, quotas | Not done or not read. Every block's address, filesystem id and level are checked; the log tree is named in a warning |
| Btrfs | Read-only snapshots (snapper's `.snapshots`, `btrfs subvolume snapshot -r`) | Listed as empty directories and named in one warning, so the listing is not repeated per snapshot. Subvolumes neither under `/` nor mounted by `/etc/fstab` are named in a warning and not walked |
| Btrfs | Zoned devices, the extent tree v2 and RAID stripe tree formats | The volume is not opened |
| ZFS | Members in other images (a pool over several disks imaged one per file), dRAID, RAID-Z with a child missing (parity is never read: nothing is reconstructed), a mirror with every side missing, removed (indirect) vdevs, RAID-Z expansion | One warning names the vdevs not in the image; files stored only there are listed but not read (metadata usually has copies elsewhere). A pool that uses a read feature the reader does not know (RAID-Z expansion, redacted datasets, a newer one) is not opened and its partition counts as having no supported filesystem |
| ZFS | Checksum verification, intent log replay, native encryption, extended attributes and ACLs, snapshots and bookmarks, the contents of zvols, case-insensitive lookup | Not done or not read. Structure is checked: block types, levels, sizes, magic numbers. Warnings name the datasets with intent log records (as a read-only import, the log is not replayed), encrypted datasets (not mounted, as on a system without the key), zvols and the number of snapshots |
| ZFS | Boot environments other than the one read as `/`; datasets with `canmount=off` or `noauto`, `mountpoint=none`, or `mountpoint=legacy` with no `zfs` line in `/etc/fstab`; a second dataset with the same mountpoint | Not walked; each group is named in one warning |
| Disk images | Virtual machine disks that need another file or a key: qcow2 with a backing file, with an external data file or encrypted (AES, LUKS); VMDK snapshots and linked clones (`parentCID` not `ffffffff`) and ESXi delta or raw-device extents (`VMFSSPARSE`, `SESPARSE`, `COWD`, `VMFSRDM`, `VMFSRAW`); differencing VHD, VHDX (has a parent) and VDI (undo or differencing); qcow2 with unknown incompatible features, VDI before header 1.1 | The run stops with an error that names the reason (and the backing file or parent where the file names one). Consolidate the chain first: `qemu-img convert -O raw` |
| Disk images | Snapshots inside a qcow2 file (the active state is read, with a warning); a VHDX whose log is not empty (disk not closed cleanly) | The disk is read without replaying the log: the writes still in it may be missing. One warning says so |
| Disk images | A compressed raw image (`.raw.gz`, `.dd.zst`) | The run stops with an error. Decompress it first |
| LVM2 | Striped, RAID, mirror, thin, cache and snapshot logical volumes; a segment on a physical volume that is not in the image | Each such volume is named in a warning and skipped. Linear logical volumes (one or many segments, on one or several physical volumes in the image) are read from the newest metadata copy, and appear as `<vg>-<lv>` |
| Software RAID | RAID6 with a member missing; RAID10 in the far and offset layouts (and near with fewer than two copies); an array being reshaped; a RAID0 of unequal members whose layout was not recorded; multipath and faulty levels; the write journal and partial parity log (not replayed); an array inside an array | Each such array is named in one warning with the reason and left out, and its members are listed in the error if nothing else is readable. Read: metadata 0.90, 1.0, 1.1 and 1.2 (checksum and position checked); linear; RAID0 including unequal members and both multi-zone layouts; RAID1 from the member with the most events (a disagreement is named); RAID10 near with two or more copies, also with members missing while every chunk keeps a copy; RAID4 and RAID5 in all layouts, with one member missing rebuilt by XOR (members that missed updates are treated as missing); RAID6 with every member. A superblock written by a big-endian machine is not recognised, and a partition table inside an array is not looked for (the array is then reported as having no supported filesystem). A mid-resync RAID5 may have parity that does not match its data, which matters only for a rebuilt member. Arrays are named `md-<name>` (or the first 8 hex of the uuid) and a filesystem, LVM2 or LUKS in them is handled as in a partition (LVM2 notes number an array 1000 and up) |
| Software RAID in several images | Members in a folder of images are found only beside the evidence file given with `-f` (at most 32 regular files examined, in name order, links never followed, later `.E02`/`.002` segments skipped), only when the array lacks a member (a RAID1 is complete with one) and only for raw, split-raw and E01 images | The files that supplied members are named in a warning. Members in a different folder are not found: put the images together |
| One host per disk | Volumes of a root that its fstab does not name (or names by a device that cannot be resolved here: Btrfs, vfat, NTFS, a uuid or label read only for ext4 and XFS, a plain `/dev/sdXN` unless the root itself is named that way, an LV or array that was not assembled), a volume mounted by two roots, a root that is itself mounted (a second operating system), bind mounts, overlay and network mounts | The volume stays a host of its own (the first root in volume order takes a shared one). A mount point that would leave the root, a mount point used twice and a mount of a volume already placed are ignored and counted in one warning; only the first 1 MiB of `etc/fstab` is read. Under a mount point the mounted volume's files win, as on a running system: files the root volume has below it are not listed (one warning with the count). The mount point directory itself is listed with the root volume's own times, not those of the mounted volume's root |
| UFS | Replaying the soft-updates journal (SU+J), gjournal, NetBSD's WAPBL log or the Solaris UFS log; reading snapshot files (`.snap`); extended attributes and ACLs (UFS2 `di_extb`, Solaris shadow inodes); inodes no directory reaches | A filesystem that was in use when imaged is read as it is on disk with one warning (`the filesystem was in use when it was imaged (not cleanly unmounted) and is read as it is on disk; its soft-updates journal (.sujournal) is not replayed: ...`, or `...; its UFS log is not rolled into it: ...` on Solaris). Snapshot files are listed with their size; reading one fails with `inode N is a UFS snapshot, which is not read` |
| APFS | Encrypted (FileVault) and sealed system volumes; LZVN and LZFSE compressed files; reading inside snapshots | Volumes are listed; unreadable files are listed with their size but not read |
| ext4 | Deleted-file recovery. In the journal: an external journal device, the fast-commit area, and the checksums of logged data blocks (superblock, descriptor, revoke and commit block checksums are verified) | A volume imaged while in use (a snapshot of a running machine) has its internal journal replayed in memory, as the kernel does on mount; the image is never written. A warning says how many transactions were replayed. An external, unreadable or damaged journal is named in the warning: transactions before the damage are replayed, and the files written last, typically the active logs, may be missing, out of date or unreadable. With fast commits on, changes after the last full commit may be missing |
| Filesystems | Extended attributes (other than ext4 inline data and APFS symlinks and compression) | Not read |
| APFS snapshots | Writing them out as an artifact | The APFS reader lists snapshot names, times and ids; no artifact writes them out yet |
| Collections | Archives inside a collection, other than CatScale's (whose inner archives are read as one host) and a UAC collection wrapped in another archive | Not opened. Extract them first |
| Collections | CatScale's command output other than `ps`, `netstat`/`ss`, `lsof` and `lsmod` (`last`, `lastlog`, package lists, `systemctl`, `crontab -l`) | Not parsed; the collected files (`wtmp`, `lastlog`, the package databases, unit files, crontabs) are |
| Collections | A folder of collections more than three levels deep, or holding more than 4,096 entries above the archives (`-d` opens the archives and images up to three levels down when the folder is not itself a host) | Point `-d` at the folder that holds the archives. A folder that is already an extracted host is read as one host: archives inside it are not opened |
| Process accounting | Version 1 (m68k) and versions 4 and 5 (a 128-byte layout the kernel never shipped); a big-endian version 0 file | A file with no readable record is a format error naming the version; records of an unknown version among readable ones are skipped with one warning that counts them. Version 0 has no version byte, so its byte order cannot be told and little-endian is assumed. `pid` and `ppid` are empty in versions 0 and 2, which do not store them; the I/O counters are not output (the Linux kernel writes zero). The record is written when the process exits, so the file is in exit order while the event time is the start time |
| Coredumps | The contents of core files | `coredump` reads the file name (command, uid, boot id, pid, time) and the first 1 MiB of an ELF64 core (plain, zstd, xz or lz4) for the start of the command line; the signal, the executable path and the memory image are not read. A source that reads whole files (a disk image) still reads the whole core into memory before the parser sees it |
| Crash reports | The text after the first binary field of an apport report, the `coredump` and `vmcore` of ABRT and kdump, the 32-bit ELF cores | Not read: apport reports are read up to their first `CoreDump: base64` field (the text fields come first), so a 525 MB report costs 3.9 MiB of resident memory; ABRT reads the small one-value files of the directory |
| sudo | The streams of an I/O log (`ttyin`, `ttyout`, `stdin`, `stdout`, `stderr`), `sudoreplay` playback, `sudo_logsrvd` stores, and the timing of sudo 1.7 (two columns) | The streams are never read (they can hold passwords): a session record has its length and the bytes per stream from `timing`. A timing line that is not understood is counted in a warning. The cache `ts/` files are counted, not decoded: their times are monotonic clock readings, so the file's modification time is the last authentication |
| Failed logins | `pam_tally2`'s `tallylog` and shadow's `faillog` from a big-endian machine, `faillog` with other record sizes than 24 and 32 bytes | The byte order is chosen by which gives plausible times; a file that is not a whole number of records is read up to its last whole one with a warning. The 24-byte (32-bit time) faillog was written by the real tool on i386 and read from that 2011 image; the big-endian case is synthetic |
| sysstat | Data files other than format 0x2175 (sysstat 12.5 and later), files from 32-bit or big-endian machines, the activities other than CPU, memory and swap level, queue, process creation, network devices and disks (interrupts, paging, sockets, NFS, power and so on), and the text `sar` files | `unsupported sysstat file version X.Y.Z` (data file format and reason) skips the file; an activity whose layout version differs from the validated one is named in a warning and not read. Disks have only `major:minor` (the names come from the running system). Rates are those of `sar -u`, `-w`, `-n DEV` and `-d` from two consecutive samples, so the first sample after a start has none. Checked: sysstat 10.1.5 (format 0x2171) is skipped; 12.5.4, 12.6.1 and 12.7.7 are read |
| atop | `var/log/atop/atop_YYYYMMDD` raw logs | Not read. The records are zlib streams of per-process structures that change with each atop version, and no reference (`atop -r -P`) was set up to validate a layout, so none was guessed |
| Tool histories | The `~/.mongosh/*_log` logs; PSReadLine's multi-line commands (a backtick continues a command) | Not read; PowerShell lines are one record each |
| Desktop | GNOME `gvfs-metadata` (binary metatree; no `gio info` ground truth could be produced headless), `dconf/user`, `tracker3`, `zeitgeist`, `gnome-shell/application_state`, keyring files (presence only), `gtk-3.0/bookmarks`, KDE `kactivitymanagerd` and `RecentDocuments`, `Xorg.*.log`, `AccountsService`, display-manager logs, `fstab`/`mtab`/`udisks2` | Not read. The files that are in the body file and the timeline appear there |
| Desktop | LibreOffice `registrymodifications.xcu` recent documents (no vendor description of the history nodes could be checked), Thunderbird profiles, the `Top Sites`, `Shortcuts`, `Network Action Predictor`, `Web Data`, `Sessions/` and `DIPS` files of Chromium, Firefox `formhistory.sqlite` | Not read |
| Services | MongoDB, Redis, Caddy, Traefik, Varnish, Suricata, OpenVPN, unbound, dnsmasq, firewalld logs, Apache `ssl_request_log` and `suexec.log`, ProFTPD's own log and pure-ftpd, JBoss and WildFly, Tomcat's two-line `SimpleFormatter` layout, PostgreSQL with another `log_line_prefix` than `%m [%p] ` or `%m [%p] %q%u@%d `, the concurrent ModSecurity audit format, NetworkManager's `*.lease` files | Not read: no real daemon was run for them. `syslog` and `journald` still read the same lines where a syslog daemon carries them |
| Services | Per-message mail and per-request proxy semantics beyond one record per log line | A Postfix `to=` record joins the client and SASL user of its queue id from the earlier `client=` line, with at most 200,000 queue ids kept at once; past that the table is dropped and one warning says so |
| Kubernetes | etcd data (`var/lib/etcd`, k3s's kine database), Secrets and ConfigMaps as stored, and everything inside a container's filesystem | Not read. Pods' own state is in the pod and container logs, the containerd metadata, the audit log and the manifests |
| Kubernetes | `var/log/pods` and `var/log/containers` logs are read as one task each (not split into chunks), because a partial (`P`) line is joined from its fragments. A `P` fragment that ends the file, changes stream or passes 1 MiB is output as it stands with `complete` false | The kubelet rotates these files at 10 MiB by default, so a task is small. `var/log/containers/*.log` symlinks are not followed; a collection that dereferenced them is read twice (the pod directory and the symlink name) |
| Kubernetes | Manifests are read by a small block-YAML reader (no YAML dependency in the artifacts crate). It does not read anchors and aliases, merge keys, tab indentation, multi-line plain or quoted scalars, or nesting past 40 levels; values produced by Helm or kustomize; or the `valuesContent` of a k3s `HelmChart` | A document it cannot read is kept as text with `parsed` false and one warning naming the line. RKE2's `var/lib/rancher/rke2` paths are not read (same layout, different stock files) |
| Kubernetes | CRI-O (`var/lib/containers/storage/overlay-containers/containers.json`) | Matched by the `podman-containers` pattern and its pod logs by `k8s-pod-logs`, but not verified: CRI-O was not run. k3s's non-systemd `var/log/k3s.log` (klog lines) is not read; the kubelet, containerd and k3s logs of systemd hosts are in the journal and `syslog` |
| Kubernetes audit | The audit log exists only if the cluster was started with an audit policy; its `requestObject` and `responseObject` are not output (they hold Secret data), and `RequestReceived` events are written only if the policy asks | Timeline events are made for `exec`, `attach`, `portforward`, secret reads, creates, deletes and changes of pods, roles and bindings by users that are not cluster components (`system:node:*`, `system:kube-*`, `system:serviceaccount:kube-system:*`, `system:k3s-*`, `k3s-*`, `system:apiserver`) and for anonymous requests. A request through a stolen component credential is not told from the component |
| Cloud | Google Cloud guest agent, OS Login and startup scripts | No artifact: they write to the journal (`google_guest_agent`, `GCEGuestAgent`, `google_metadata_script_runner`, `google_osconfig_agent`, `google-startup-scripts`), which `journald` reads, and `google_sudoers` is read as a sudoers file. Startup script copies under `/tmp` are deleted by the runner and are not looked for |
| Cloud | AWS `var/log/amazon/ssm/audits/`, `var/log/amazon/efs`, `var/awslogs`, Azure `var/log/azure/<extension>/` handler logs and `var/lib/waagent/history` | Not read |
| Credential files | The contents of `credentials.db`, `access_tokens.db`, `msal_token_cache.json`, `~/.vault-token`, private keys and every token, password and `auth` value | Never read into a record: the file, its size, mode and time are, and the profile, account, registry and host names. An AWS access key ID is output as its first and last four characters, enough to look it up in CloudTrail |
| Remote access | Splashtop, DWService, chisel, gost, rathole, reverse-ssh, JetBrains Gateway, OpenVPN status files, RustDesk server logs, TeamViewer and AnyDesk logs beyond their line format | Not read. An `ssh -R/-L/-D` or `autossh` command in a unit, cron or at line, and the programs named in the persistence hunter, are detected in the existing artifacts' records |
| Remote access | Timestamps of AnyDesk, TeamViewer and VS Code server logs, and of the AnyDesk and TeamViewer connection lists | They carry no zone: the host's zone is assumed and `basis` says so. TeamViewer's list is read as day-month-year |
| macOS | Spotlight stores (`.Spotlight-V100`), keychain databases (`*.keychain-db`), `launchd.log`, `wifi.log` and other text logs under `Library/Logs`, Saved Application State `windows.plist`, `Application Scripts`, Dock tile plug-ins, Automator Quick Actions, the Folder Actions dispatcher plist | Not read. Spotlight and keychain formats were not implemented because they could not be validated; the text logs have no format reference that was checked. MRT and XProtect Remediator results, AirDrop and `backupd` messages are in the Unified Log, which `unified-log` reads |
| macOS | Contacts, Notes, Calendars | Skipped on purpose: personal content with low incident-response value |
| Windows | Everything | Out of scope |
| AIX | The binary error log, the circular alog files, ODM classes and the binary audit trail | Not read: no layout confirmed by two independent sources. The saved `errpt`, `alog -o`, `lslpp` and `lssrc` output is read instead |
| AIX | `lsuser`, `lsgroup`, `who -a` and `last` output; raw `snap` bundles | Not parsed; the files behind them (`etc/security/*`, `wtmp`) are |

## VMware ESXi

No ESXi host could be run during development (the software needs a vendor login), so every
ESXi parser was checked against public logs and files written by real hosts, or is marked
synthetic below. Real data used (never copied into the repository; the test fixtures are
synthetic lines in the same layouts, with documentation addresses):

- a public ESXi 6.7.0 `vm-support` bundle of a lab host (build 19195723, 2026), the folder
  `esx-<host>-<date>-<id>` in <https://github.com/saishashank-a/Predictive-Analysis-Report>;
- the test data of an ESXi forensics library, <https://github.com/puffyCid/artemis-api>
  (`tests/test_data/esxi`: an ESXi 8.0.3 `shell.log`, `syslog.log` and `syslog.5.gz`, a VIB
  descriptor and `passwd`);
- a 2021 `shell.log` from <https://github.com/Qazeer/Vector4IR> (`tests/data`);
- sample lines of ESXi 6.x, 7.x and 8.0 logs in the format definitions of
  <https://github.com/tstack/lnav> (`src/formats/vmk_log.json`, `vmw_log.json`,
  `esx_syslog_log.json`), read to confirm the 8.0 layout (`In(14) shell[pid]:`); and UAC 3.4.0's
  `artifacts/` for what its `esxi` profile collects, <https://github.com/tclahr/uac>.

| Artifact | Checked against | Result |
|---|---|---|
| `esxi-shell` | the 6.7 bundle (67 lines), the 8.0.3 sample (164 lines) and the 2021 sample (7 lines) | Every line is a record; `executed` events equal the lines of the form `[user]: command`, counted separately (27 of 27, 159 of 159 and 1 of 1) |
| `esxi-hostd` | the 6.7 bundle: `hostd.log` and three rotations, 300,801 lines | Every line is a record. Events equal a count of the same message forms made outside nixcavate: logins 552 of 552, logouts 477, failed logins 55, lockouts 37, VMs powered on 256, powered off 218, removed 55, registered 7, created 52. 39.8% of the lines have no time: they continue a multi-line dump (`-->`) |
| `esxi-vob` | the 6.7 bundle: `vobd.log` and a rotation, 9,931 lines | Every line is a record; 5,414 of 5,414 event ids equal a count made outside nixcavate |
| `esxi-vmkernel` | the 6.7 bundle: `vmkernel.log`, seven rotations and `vmkwarning.log`, 98,973 lines | Every line is a record; 85,335 have the `cpuN:world)` part. The early-boot lines before the clock was set have no time and no CPU, and are kept |
| `esxi-daemon-log` | the 6.7 bundle: `vpxa`, `rhttpproxy`, `hostd-probe`, `vsansystem`, `vvold` and rotations, 189,974 lines | Every line is a record; the client address of all 2,667 `New proxy client` lines in `rhttpproxy` is read (1,834 `SSL(...)` and 833 plain) |
| `esxi-syslog` | the 6.7 bundle (22 files, 89,372 lines) and the 8.0.3 sample (9,435 lines) | Every line is a record. Events equal outside counts: `Host has booted` 30 of 30, esxupdate commands 72 of 72, cron jobs 2,006 of 2,006 and 183 of 183, sftp uploads 8 of 8, sftp removals 1 of 1 |
| `esxi-auth-log` | the 6.7 bundle, 48 lines | Every line is a record; accepted logins 1 of 1 and failed ssh logins 3 of 3, classified as `auth-log` does |
| `esxi-vm-log` | one 6.7 `vmware.log`, 2,319 lines | Every line is a record; the power-on and the `VMX has left the building` lines are the two events |
| `esxi-sysboot` | the 6.7 bundle, 139 lines | Every line is a record |
| `esxi-vib` | one real descriptor (community level, with install date) | Fields and the install time equal the file |
| `esxi-vib-list` | a real 6.7 `esxcli software vib list`, 150 rows | 150 of 150 |
| `esxi-config` | the real `esx.conf` and `etc/vmware/config`, 525 lines | 525 of 525 |
| `esxi-host-config`, `esxi-vm-inventory`, `esxi-permissions`, `esxi-firewall-rules` | the real `hostsvc.xml`, `vpxa.cfg`, `vmInventory.xml`, `authorization.xml`, `service.xml` and `vsanhealth.xml` | 43 of 43 leaves, 23 of 23 VMs, 3 of 3 permissions, 91 of 91 rules (counted outside nixcavate) |
| `esxi-live-connections`, `esxi-live-processes`, `esxi-live-vm-processes` | the real `localcli network ip connection list`, `ps -cPTgjstz` and `vm process list` | 61 of 61 connections; 702 of 704 processes (the two others, a zombie and an `Invalid` world, have too few columns and are warned about); 3 of 3 VMs |
| `esxi-rc-local`, `esxi-rc-local-files` | the stock `local.sh` and the files of `rc.local.d` of the 6.7 bundle | The stock script gives only `exit 0`, which the hunter ignores |

The same bundle read as a `.tgz` gives the same host name, version and record counts as the folder.
Speed: the 5.9 MiB `hostd.log` is parsed in about 19 ms on one thread (about 310 MiB/s), the same as the
Linux `syslog` artifact on a copy of the same file.

**Synthetic only** (built from the documented or observed layout, no real sample of this exact case):

- *ESXi 8.0 `hostd.log`, `vmkernel.log`, `vobd.log` and `vmware.log`.* Real 8.0 samples of `shell.log`,
  `syslog.log` and the header of other logs exist; the full 8.0 daemon logs only as one lnav sample
  line each. The header parser reads the 8.0 form (`2022-06-02T02:56:51.118Z Db(167) Hostd[pid]: [Originator@6876 ...]`)
  and the tests use it, but no complete 8.0 `hostd.log` was checked.
- *The `vm_snapshot` event* (`Task: Create virtual machine snapshot`): no real log of a snapshot
  was available, so the message text is from vSphere's event descriptions, not from a log.
- *`esxi-live-vm-list`* (`vim-cmd vmsvc/getallvms`): no real output was available; the columns are
  found from the header and a header that does not match is refused. `esxi-live-processes` reads only
  the exact `ps -cPTgjstz` header; UAC's `ps` variants are refused with a message (their columns
  were not seen).
- *UAC collections of ESXi.* Paths of the saved command output come from UAC's `esxi` artifact
  definitions and the `live_response/<category>/` layout of its Linux collections; no real UAC
  collection of an ESXi host was available. The end-to-end test uses a synthetic one.
- *`.FRAG-` pieces of logs.* The bundle used has pieces only for command output and libraries, not for
  logs. The repair of a line cut between pieces is tested with synthetic pieces.
- *Custom firewall rule sets, extra accounts in `authorization.xml`, a VIB with an `etc/init.d`
  file, a modified `local.sh`, `etc/ssh/keys-<user>/authorized_keys` and `/.ash_history`.* The formats
  are those of the stock files or documented; the persistence checks that judge them were exercised
  with planted files only.
- *`esx.audit` events other than those seen:* `ssh`/`shell`/`dcui` switches, `host.boot`, `host.stop`,
  `account.locked`, `dcui.login.failed`, firewall and VMFS events were seen; the rest are `audit` events
  by their id prefix only.

**Not supported**

| What | What happens |
|---|---|
| ESXi 5.x and older log layouts (`[2011-04-01 15:14:34.203 F5A5AB90 info 'vm:...'`) | The lines are records with no time |
| `envoy-access.log` (the ESXi 7.0 U2 and later reverse proxy access log) | Not read; no sample was available |
| `bootbank/local.tgz` and `imgdb.tgz` (the saved configuration and the image database), `var/db/esximg/profiles` | Not read. A bundle's `etc/` is the running configuration |
| `esxcfg-info`, `localcli` and `esxcli` outputs other than the five above | Not parsed (the files stay in the evidence) |
| Logs under `scratch/log` when `var/log` is a link to it that was not collected | Not read; `var/log` and `var/run/log` are |
| VMFS datastores as disks, and `.vmx`, `.vmsd` and `.vmdk` descriptors | Not read. `vmware.log` files inside a collected datastore folder are |
| The timeline of `esxi-vmkernel` | Only `WARNING`, `ALERT` and error lines; every other line is a record with no event, as the log has hundreds of thousands per day |
| `esxi-hostd` multi-line dumps | A line that continues a dump is a record with no time (a split file cannot carry the time of the line before it) |
| Pieces of a `.FRAG-` file whose neighbour is missing | The first line of a piece whose predecessor is missing is dropped as the tail of a cut line; a last line with no newline is kept as it is |
| `esx.conf` and XML values for keys naming `password`, `secret`, `chap`, `community`, `credential`, `token` or `private` | Withheld: `redacted` is true and `value` is empty. `shadow` shows the hash type only, as on Linux |

## Virtual machine disks

qcow2 (versions 2 and 3: standard, zero, deflate and zstd compressed clusters, extended L2
subclusters, cluster sizes 512 bytes to 2 MiB), VMDK (hosted sparse extents, `streamOptimized`,
descriptors with `FLAT`, `VMFS` and `SPARSE` extents, so `monolithicSparse`, `twoGbMaxExtentSparse`,
`monolithicFlat`, `twoGbMaxExtentFlat` and ESXi `-flat.vmdk` disks), VHD (fixed, whose 512-byte footer
is not part of the disk, and dynamic), VHDX (dynamic and fixed) and VDI (dynamic and static, header 1.1)
are read directly, as the disk they hold: no conversion, no temporary file. Checked against
`qemu-img` 7.2 (every variant above converted from one 8 MiB GPT/ext4 disk and read back byte for
byte; thousands of mutated headers and tables per format with no panic) and against a real Debian 12
cloud image (3 GiB) as qcow2, compressed qcow2, VMDK sparse and flat, VHDX, VDI and VHD:
the SHA-256 of the whole virtual disk equals the raw original's, and `auto-parse` gives the same
254 succeeded and 4 skipped tasks and the same records. A 200 GiB, 32-extent `twoGbMaxExtentSparse`
VMDK matched `qemu-img dd` on 20 random 1 MiB ranges, and a 32 GiB fixed VHD parses as before.

- Extent files of a VMDK descriptor are looked for in the descriptor's own directory only, by the
  last component of the name (case-insensitively if needed); absolute names and `..` are refused
  and symbolic links are not followed. A missing extent is one warning and reads in its range fail.
- A VHD created from a CHS geometry (Virtual PC style) may be a little larger than the data it was
  made from; the extra bytes read as zeros.
- Unallocated, zero and (VHDX) unmapped blocks read as zeros, as they do for a disk with no parent.
- VMDK extents of type `VMFS` are read as the plain flat files they are (a parent is still refused).

## Behavior to know

- **Bytes that are not UTF-8 text are replaced.** In a journal field or a log line, each
  such byte becomes U+FFFD, with no warning. `source_path` and `source_offset` lead back to
  the original bytes.
- **A disk image whose only filesystem is not read** (F2FS, NTFS, an encrypted volume)
  stops the run with an error that names it. Mount it and pass the mounted folder with `-d`.
- **A Btrfs volume is shown as its system mounts it.** `/` is the default subvolume; when
  that is the top level and has no `/etc` but a subvolume directly under it does (`root` on
  Fedora, `@` on Ubuntu, Arch and openSUSE layouts), that subvolume is `/`. The subvolumes
  that `/etc/fstab` mounts (`subvol=`, `subvolid=`) appear at their mount points, and
  writable subvolumes nested in a shown one appear where they are. A note says which
  subvolume was taken as `/` and what was mounted where. Inode numbers in the body file are
  those of the subvolume read as `/`; files of other subvolumes carry the subvolume's slot in
  bits 48 and up.
- **A ZFS pool is shown as its system mounts it.** `/` is the dataset the pool's `bootfs`
  property names (FreeBSD, illumos); without one, the dataset whose `mountpoint` is `/` (with
  `canmount` on before `noauto`, then the one written last);
  without one, a `legacy` or `none` dataset that holds `/etc`. Every other dataset that mounts
  at boot appears at its `mountpoint` (an inherited one is the parent's plus the dataset's
  name, as `zfs` computes it), legacy datasets where the root's `/etc/fstab` mounts them.
  With no root dataset (a data pool), `/` is an empty directory holding the datasets at their
  mountpoints (`/tank`, `/tank/home`). Members of one pool that are partitions of the same
  image are joined (mirror, stripe, RAID-Z); the pool is one volume, named after its first
  member. Inode numbers in the body file are the object numbers of the dataset read as `/`;
  files of other datasets carry the dataset's slot in bits 48 and up.
- **NUL padding in a log is skipped.** Rotation that copies and truncates, and an unclean
  shutdown, leave runs of NUL bytes. NUL bytes at the start of a line are dropped, and so is
  a line made only of them.
- **Zone-less times depend on the host zone.** If the evidence has neither zone data nor a
  zone name, UTC is assumed. The manifest's `timezone` field says what was used; every such
  timestamp is marked `assumed_zone`.
- **Year inference can be wrong** for a syslog line more than a year older than its file's
  last write. Such timestamps are marked `inferred_year`.
- **File modification times come from the collection.** tar keeps them. Zip stores local
  time with no zone, read as UTC. A plain directory copy may have reset them, which also
  affects year inference. `input_modified` in the manifest shows what was seen.
- **Expansion is limited.** A compressed log or archive that expands more than 100 times is
  cut (`--max-expansion`). The task fails, keeps what it parsed, and the manifest shows the
  span covered.
- **Two hosts with one name** get separate output folders (`name`, `name-2`), but their
  manifest tasks and records carry the same `host` value. Use the output path to tell them
  apart.
- **A mounted volume is walked in full** before parsing, which takes seconds per million
  files.
- **Memory-mapped reads abort on I/O errors.** If evidence on failing media or a network
  share returns an error mid-read, the operating system raises `SIGBUS` and the run stops
  without a manifest. Copy such evidence to local disk first.
- **CSV cells are written as they are.** A cell from evidence that starts with `=`, `+`,
  `-` or `@` is not neutralized, because the output must match the evidence. Do not open
  the CSV in a spreadsheet that evaluates formulas.
- **Persistence-hunter findings are heuristics.** A clean result is not proof of absence. A
  plain `modules-load.d` entry is compared with the kernel tree under `lib/modules`, which a UAC
  collection does not hold, so it is found on disk images only. The stock-line exceptions are
  exact shapes listed in `docs/PERSISTENCE_HUNTER.md`; on 109 collections (stock and scripted
  hosts, 39 distributions) the medium and high findings that were not planted fell from 313 to 8,
  and all 1,273 planted items found before were still found.
  In directory mode, file ownership is that of the extracting user, so the
  ownership checks are only meaningful for archives and images.
- **UFS1 times with the top bit set.** UFS1 stores 32-bit seconds. FreeBSD reads them as
  unsigned (1970 to 2106) and so does nixcavate; NetBSD and OpenBSD read them as signed, so a
  time they show before 1970 is shown 136 years later here. Solaris UFS is read as signed, with
  microseconds. When FreeBSD 14 loads a UFS1 inode whose time is later than the present, it
  shows the present instead (and changes the change time); nixcavate shows what is stored.
- **BSD and Solaris partitions are numbered by their label.** The partitions a BSD disklabel
  or a Solaris VTOC makes of a slice are `p<100 * slice + n>`: `p101` is slice 1, partition
  `a` (or VTOC slice 0). A label on a disk with no other table gives `p1`, `p2`...
- **Disk images are bounded.** A volume is listed up to 20 million files, paths up to 4096
  bytes and 256 levels deep; anything beyond is skipped with a warning. A file larger than
  2 GiB, or a sparse file over 64 MiB with less than 1/16 of it allocated, is listed but not
  read.

## Performance targets not met

See [PERFORMANCE.md](PERFORMANCE.md). In short: the timeline target is met; five text parsers
(auth-log, dpkg-log, pacman-log, emerge-log, zypp-history; 157 to 208 MiB/s on one thread in
`auto-parse` with JSONL output and timeline events, on a 200 MiB log; dpkg-log is 183 MiB/s in the same
run) and the Unified Log parser are below their per-core targets; per-core
throughput is a third to a half lower in `auto-parse`, where every log line also becomes a
timeline event; and a run's wall time is set by its largest unsplittable file. `k8s-pod-logs` is not split (partial lines are joined from their fragments) and reads about 250 MiB/s on one thread (116 MiB of CRI lines, records only, CSV).
