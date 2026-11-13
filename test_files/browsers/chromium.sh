#!/bin/sh
# Chromium 1xx (Debian 12 arm64) headless: an unpacked extension with a localised name, cookies from a local server,
# and a real download via the DevTools protocol. Output: $1/chromium/profile.tar (the Default profile, Preferences,
# Secure Preferences, History, Cookies, Login Data, Web Data) and truth.txt.
set -eu
out="$1"; mkdir -p "$out/chromium"
docker run --rm --platform linux/arm64 --shm-size=1g debian:12 sh -c '
exec 3>&1 1>&2
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq chromium python3 python3-websockets sqlite3 >/dev/null 2>&1
chromium --version
mkdir -p /ext/_locales/en /srv/www /prof
cat > /ext/manifest.json <<EOM
{"manifest_version": 3, "name": "__MSG_extName__", "version": "1.2.3", "description": "__MSG_extDesc__", "default_locale": "en",
 "permissions": ["tabs", "cookies", "webRequest"], "host_permissions": ["<all_urls>"], "update_url": "https://clients2.google.com/service/update2/crx",
 "background": {"service_worker": "bg.js"}}
EOM
echo "{\"extName\": {\"message\": \"Nx Test Extension\"}, \"extDesc\": {\"message\": \"Reads everything\"}}" > /ext/_locales/en/messages.json
echo "console.log(1)" > /ext/bg.js
head -c 30000 /dev/urandom > /srv/www/payload.bin
cat > /srv/www/index.html <<EOH
<html><head><title>Nx test page</title></head><body><a href="/payload.bin" download>get</a></body></html>
EOH
cat > /srv/server.py <<EOS
import http.server
class H(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        if self.path.startswith("/payload"):
            self.send_header("Content-Disposition", "attachment; filename=payload.bin")
        else:
            self.send_header("Set-Cookie", "sid=SECRETCOOKIEVALUE123; Path=/; HttpOnly; Max-Age=86400")
            self.send_header("Set-Cookie", "pref=dark; Path=/; Max-Age=3600")
        super().end_headers()
http.server.ThreadingHTTPServer(("127.0.0.1", 8123), lambda *a, **k: H(*a, directory="/srv/www", **k)).serve_forever()
EOS
python3 /srv/server.py >/dev/null 2>&1 &
sleep 1
chromium --headless=new --no-sandbox --disable-gpu --user-data-dir=/prof --load-extension=/ext --remote-debugging-port=9222 --password-store=basic about:blank >/tmp/chrome.log 2>&1 &
sleep 6
cat > /tmp/drive.py <<EOP
import asyncio, json, urllib.request, websockets, time
async def main():
    targets = json.load(urllib.request.urlopen("http://127.0.0.1:9222/json/list"))
    page = [t for t in targets if t["type"] == "page"][0]
    async with websockets.connect(page["webSocketDebuggerUrl"], max_size=None) as ws:
        n = 0
        async def call(method, **params):
            nonlocal n
            n += 1; mid = n
            await ws.send(json.dumps({"id": mid, "method": method, "params": params}))
            while True:
                msg = json.loads(await ws.recv())
                if msg.get("id") == mid: return msg
        await call("Browser.setDownloadBehavior", behavior="allow", downloadPath="/tmp/dl", eventsEnabled=True)
        await call("Page.enable")
        await call("Page.navigate", url="http://127.0.0.1:8123/index.html"); time.sleep(2)
        await call("Page.navigate", url="http://127.0.0.1:8123/payload.bin"); time.sleep(3)
        print("done", flush=True)
    # A clean shutdown: the cookie and history databases are written when the browser exits.
    version = json.load(urllib.request.urlopen("http://127.0.0.1:9222/json/version"))
    async with websockets.connect(version["webSocketDebuggerUrl"]) as ws:
        await ws.send(json.dumps({"id": 1, "method": "Browser.close"}))
        try: await ws.recv()
        except Exception: pass
asyncio.run(main())
EOP
python3 /tmp/drive.py
sleep 8
ls -la /tmp/dl /prof/Default | head -50
date -u +%Y-%m-%dT%H:%M:%SZ > /prof/.truth-end.txt
cd /prof && tar cf - --exclude=Cache --exclude="Code Cache" --exclude=GPUCache --exclude="Service Worker" --exclude="*.log" Default "Local State" .truth-end.txt >&3' > "$out/chromium/profile.tar"
