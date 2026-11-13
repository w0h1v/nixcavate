#!/bin/sh
# Runs inside a privileged Debian 12 container: each real interactive tool is run on a pty with
# a few typed lines, and the history file it writes is copied to /out.
export DEBIAN_FRONTEND=noninteractive
mkdir -p /out; exec > /tmp/log.txt 2>&1; set -x
apt-get update -qq >/dev/null 2>&1
for p in python3 nodejs sqlite3 gdb irb php-cli redis-tools postgresql-client; do apt-get install -y -qq $p >/dev/null 2>&1 || echo "cannot install $p" >> /out/notes.txt; done
useradd -m alice
mkdir -p /out
D="python3 /drive.py"
su alice -c "cd; $D 'const x = 41 + 1' 'console.log(\"hello world\")' -- node" >/dev/null 2>&1
su alice -c "cd; $D '.open /tmp/test.db' 'create table t(a text);' \"insert into t values('it works');\" 'select * from t;' -- sqlite3" >/dev/null 2>&1
su alice -c "cd; echo 'set history save on' > ~/.gdbinit; $D 'info registers' 'show version' -- gdb -q" >/dev/null 2>&1
su alice -c "cd; $D 'puts 1+1' 'puts \"a b\"' -- irb" >/dev/null 2>&1
su alice -c "cd; $D 'echo 1+1;' 'echo \"hi there\";' -- php -a" >/dev/null 2>&1
su alice -c "cd; $D 'SET name value' 'GET name' -- redis-cli -p 1" >/dev/null 2>&1
su alice -c "cd; $D 'select 1;' -- psql -h /nonexistent postgres" >/dev/null 2>&1
for f in .node_repl_history .sqlite_history .gdb_history .irb_history .local/share/irb/history .php_history .rediscli_history .psql_history; do
    [ -f /home/alice/$f ] && { mkdir -p /out/$(dirname $f); cp /home/alice/$f /out/$f; }
done
