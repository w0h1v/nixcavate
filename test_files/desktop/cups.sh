#!/bin/sh
# CUPS 2.4 (Debian 12): a queue with the generic PostScript PPD writing to /dev/null, print jobs from two users
# (lp -t sets the job title). Output: $1/cups/{page_log,access_log,error_log,c*}
set -eu
out="$1"; mkdir -p "$out/cups"
docker run --rm --platform linux/arm64 debian:12 sh -c '
exec 3>&1 1>&2
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq cups cups-client cups-filters ghostscript >/dev/null 2>&1
useradd -m alice; useradd -m bob
sed -i "s/^FileDevice.*//; s/^ErrorLog.*/ErrorLog \/var\/log\/cups\/error_log/" /etc/cups/cups-files.conf; echo "FileDevice Yes" >> /etc/cups/cups-files.conf
echo "PreserveJobHistory Yes" >> /etc/cups/cupsd.conf
sed -i "s/^LogLevel.*/LogLevel info/; s/^PageLogFormat.*/PageLogFormat %p %u %j %T %P %C %{job-billing} %{job-originating-host-name} %{job-name} %{media} %{sides}/" /etc/cups/cupsd.conf
cupsd; sleep 3
lpadmin -p nxprint -E -v file:/dev/null -m drv:///sample.drv/deskjet.ppd -o printer-is-shared=false
lpstat -p >&2
printf "quarterly report page one\n" > /tmp/report.txt; for i in $(seq 200); do echo "line $i of a longer text"; done > /tmp/long.txt
su alice -c "lp -d nxprint -t \"Q3 Financial Report\" /tmp/report.txt"
su alice -c "lp -d nxprint -t \"Resume of A. Person.docx\" -n 2 /tmp/report.txt"
su bob -c "lp -d nxprint -t \"Secret-plan.pdf\" /tmp/long.txt"
sleep 15
lpstat -W completed >&2
mkdir -p /o; cp /var/log/cups/page_log /var/log/cups/access_log /var/log/cups/error_log /o/; cp /var/spool/cups/c* /o/ 2>&1 || true
ls -la /var/spool/cups >&2; cd /o; tar cf - . >&3' | tar -C "$out/cups" -xf -
