#!/bin/sh
# A GTK/GNOME desktop session in Debian 12 under xvfb + dbus: recently-used.xbel written by GTK
# (RecentManager and real gedit/eog), the freedesktop trash written by `gio trash`, and thumbnails
# written by libgnome-desktop's thumbnail factory. Output: $1/gtk/{home.tar,truth.txt}
set -eu
out="$1"; mkdir -p "$out/gtk"
docker run --rm --privileged --platform linux/arm64 debian:12 sh -c '
exec 3>&1 1>&2
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq bubblewrap libgdk-pixbuf2.0-bin python3-gi gir1.2-gtk-3.0 gir1.2-gnomedesktop-3.0 libglib2.0-bin xvfb xauth dbus-x11 python3-pil gedit eog shared-mime-info >/dev/null 2>&1
useradd -m -s /bin/bash alice
cat > /tmp/session.py <<EOP
import os, time, datetime, subprocess, hashlib
import gi
gi.require_version("Gtk", "3.0"); gi.require_version("GnomeDesktop", "3.0")
from gi.repository import Gtk, GLib, Gio, GnomeDesktop, GdkPixbuf
from PIL import Image
home = os.path.expanduser("~")
for d in ("Documents", "Pictures", "tmp"): os.makedirs(os.path.join(home, d), exist_ok=True)
def now(): return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
truth = open("/tmp/truth.txt", "w")
def say(*a): truth.write(" ".join(str(x) for x in a) + "\n"); truth.flush()
open(home + "/Documents/report.txt", "w").write("quarterly report\n")
open(home + "/Documents/notes with space.txt", "w").write("notes\n")
open(home + "/Documents/café über.txt", "w").write("unicode name\n")
Image.new("RGB", (640, 480), (200, 30, 30)).save(home + "/Pictures/photo.png")
Image.new("RGB", (800, 600), (30, 30, 200)).save(home + "/Pictures/secret plan.jpg")
open(home + "/tmp/to-trash.txt", "w").write("trash me\n")
open(home + "/tmp/also trash %20.txt", "w").write("trash me too\n")
os.makedirs(home + "/tmp/dir-to-trash/sub"); open(home + "/tmp/dir-to-trash/sub/f", "w").write("x")
open(home + "/tmp/purged.txt", "w").write("trashed then purged\n")
# 1. recent files through the GTK API, one of them twice (applications count).
rm = Gtk.RecentManager.get_default()
def add(path, app, exe, groups):
    uri = Gio.File.new_for_path(path).get_uri()
    mime = Gio.content_type_guess(path, None)[0]
    data = Gtk.RecentData(); data.display_name = os.path.basename(path); data.mime_type = mime
    data.app_name = app; data.app_exec = exe; data.is_private = False
    rm.add_full(uri, data); say("recent", now(), uri, mime, app)
for p, app, exe in ((home + "/Documents/report.txt", "nxapp", "nxapp %u"), (home + "/Documents/notes with space.txt", "nxapp", "nxapp %u"), (home + "/Documents/café über.txt", "other", "other %f")):
    add(p, app, exe, ["Office"])
    for _ in range(40):
        GLib.MainContext.default().iteration(False); time.sleep(0.02)
time.sleep(1); add(home + "/Documents/report.txt", "nxapp", "nxapp %u", ["Office"])
loop = GLib.MainLoop(); GLib.timeout_add(1500, loop.quit); loop.run()
# 2. real applications opening files.
for cmd, f in ((["gedit", "--standalone"], home + "/Documents/report.txt"), (["eog"], home + "/Pictures/photo.png")):
    p = subprocess.Popen(cmd + [f], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); say("open", now(), cmd[0], f)
    time.sleep(8); p.terminate(); p.wait()
# 3. trash.
for f in ("tmp/to-trash.txt", "tmp/also trash %20.txt", "tmp/dir-to-trash", "tmp/purged.txt"):
    subprocess.run(["gio", "trash", home + "/" + f], check=True); say("trash", now(), home + "/" + f)
    time.sleep(1.1)
for name in os.listdir(home + "/.local/share/Trash/files"):
    if name == "purged.txt": os.remove(home + "/.local/share/Trash/files/" + name); say("purge from Trash/files", now(), name)
# 4. thumbnails.
fac = GnomeDesktop.DesktopThumbnailFactory.new(GnomeDesktop.DesktopThumbnailSize.NORMAL)
for p in (home + "/Pictures/photo.png", home + "/Pictures/secret plan.jpg"):
    uri = Gio.File.new_for_path(p).get_uri(); mtime = int(os.path.getmtime(p)); mime = Gio.content_type_guess(p, None)[0]
    pix = fac.generate_thumbnail(uri, mime)
    fac.save_thumbnail(pix, uri, mtime); say("thumbnail", now(), uri, mtime, mime, hashlib.md5(uri.encode()).hexdigest())
bad = home + "/Documents/report.txt"; fac.create_failed_thumbnail(Gio.File.new_for_path(bad).get_uri(), int(os.path.getmtime(bad))); say("failed-thumbnail", now(), bad)
# A deleted original: the thumbnail stays.
os.remove(home + "/Pictures/secret plan.jpg"); say("delete original", now(), home + "/Pictures/secret plan.jpg")
EOP
chown alice /tmp/session.py
su alice -c "cd ~ && xvfb-run -a dbus-run-session -- python3 /tmp/session.py" 
cp /tmp/truth.txt /home/alice/.truth.txt
cd /home/alice && tar cf - .local/share/recently-used.xbel .local/share/Trash .cache/thumbnails .truth.txt Documents Pictures >&3' > "$out/gtk/home.tar"
