#!/bin/sh
# Rebuilds the service-log fixtures with the real daemons in throwaway Docker containers (arm64):
#   sh test_files/svclogs/build.sh <output-dir>
# Each script writes one folder per daemon under <output-dir>; copy what a test needs into
# test_files/svclogs/. Needs Docker and network access. The desktop and browser fixtures are built
# by test_files/desktop/*.sh and test_files/browsers/*.sh in the same way. Rebuilding changes every
# timestamp, so the tests' expected times must be updated with it.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:?output directory}"
for script in mail exim postgres haproxy_squid named_f2b ftp_samba dhcp modsec_tomcat mysql; do
    sh "$here/$script.sh" "$out"
done
