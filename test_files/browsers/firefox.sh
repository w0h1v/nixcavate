#!/bin/sh
# Firefox ESR (Debian 12 arm64) headless with a fresh profile: cookies from a local server, history, and the profile's
# own extensions.json, prefs.js and sessionstore. Output: $1/firefox/profile.tar
set -eu
out="$1"; mkdir -p "$out/firefox"
docker run --rm --platform linux/arm64 --shm-size=1g debian:12 sh -c '
exec 3>&1 1>&2
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq firefox-esr python3 xvfb >/dev/null 2>&1
firefox-esr --version
mkdir -p /srv/www /fp
echo "<html><head><title>Nx test page</title></head><body>hi</body></html>" > /srv/www/index.html
cat > /srv/server.py <<EOS
import http.server
class H(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Set-Cookie", "sid=SECRETCOOKIEVALUE123; Path=/; HttpOnly; Max-Age=86400")
        self.send_header("Set-Cookie", "pref=dark; Path=/; Max-Age=3600")
        super().end_headers()
http.server.ThreadingHTTPServer(("127.0.0.1", 8124), lambda *a, **k: H(*a, directory="/srv/www", **k)).serve_forever()
EOS
python3 /srv/server.py >/dev/null 2>&1 &
sleep 1
cat > /fp/user.js <<EOP
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "proxy.example.test");
user_pref("network.proxy.http_port", 3128);
user_pref("network.trr.mode", 2);
user_pref("network.trr.uri", "https://dns.example.test/dns-query");
user_pref("xpinstall.signatures.required", false);
user_pref("app.update.auto", false);
EOP
export MOZ_HEADLESS=1 HOME=/root
timeout 40 firefox-esr --headless --no-remote --profile /fp http://127.0.0.1:8124/index.html >/tmp/ff.log 2>&1 &
sleep 25
pkill -TERM firefox-esr || true; sleep 8
ls -la /fp | head -50
cd /fp && tar cf - --exclude=cache2 --exclude=startupCache --exclude="*.lz4tmp" --exclude=storage --exclude=datareporting --exclude=crashes . >&3' > "$out/firefox/profile.tar"
