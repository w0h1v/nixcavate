#!/usr/bin/env python3
"""Writes synthetic preference property lists (Finder, Dock, login window, Spotlight shortcuts).
Example data only. Run: python3 generate.py"""
import datetime, os, plistlib, struct
here = os.path.dirname(os.path.abspath(__file__))
ex = os.path.join(here, "..", "sharedfilelist")


def dump(name, obj):
    with open(os.path.join(here, name), "wb") as f:
        plistlib.dump(obj, f, fmt=plistlib.FMT_BINARY)


def item_text(s):
    b = s.encode()
    return struct.pack("<II", len(b), 0x0101) + b


def bookmark(parts):
    area = bytearray(4)
    offs = []
    for p in parts:
        offs.append(len(area))
        area.extend(item_text(p))
        while len(area) % 4:
            area.append(0)
    arr = len(area)
    area.extend(struct.pack("<II", 4 * len(offs), 0x0601) + b"".join(struct.pack("<I", o) for o in offs))
    root = len(area)
    area.extend(item_text("/"))
    while len(area) % 4:
        area.append(0)
    toc = len(area)
    struct.pack_into("<I", area, 0, toc)
    area.extend(struct.pack("<IIIII", 12 * 2 + 12, 0xFFFFFFFE, 1, 0, 2))
    area.extend(struct.pack("<III", 0x1004, arr, 0) + struct.pack("<III", 0x2002, root, 0))
    return b"book" + struct.pack("<III", 48 + len(area), 0x10040000, 48) + b"\0" * 32 + bytes(area)


dump("com.apple.finder.plist", {
    "FXRecentFolders": [{"name": "Documents", "file-bookmark": bookmark(["Users", "alice", "Documents"])},
                        {"name": "Downloads", "file-bookmark": b"junk"}],
    "GoToFieldHistory": ["/tmp/payload", "~/Library/LaunchAgents"],
    "FXDesktopVolumePositions": {"Macintosh HD_0x1234": {}, "EVIL-USB_0x9abc": {}},
    "FXConnectToLastURL": "smb://files.example.com/share",
})
tile = lambda label, bid, url: {"tile-type": "file-tile", "tile-data": {
    "file-label": label, "bundle-identifier": bid, "file-data": {"_CFURLString": url, "_CFURLStringType": 15}}}
dump("com.apple.dock.plist", {
    "persistent-apps": [tile("Safari", "com.apple.Safari", "file:///Applications/Safari.app/"),
                        tile("Helper", "com.example.helper", "file:///Users/alice/Downloads/Helper.app/")],
    "persistent-others": [tile("Downloads", "", "file:///Users/alice/Downloads/")],
    "recent-apps": [tile("Notes", "com.apple.Notes", "file:///System/Applications/Notes.app/")],
})
dump("com.apple.loginwindow.plist", {
    "LoginHook": "/Users/Shared/.hook.sh", "LogoutHook": "/tmp/logout.sh", "autoLoginUser": "alice",
    "lastUser": "loggedIn", "lastUserName": "alice", "GuestEnabled": False, "SomethingElse": "ignored",
    "TALAppsToRelaunchAtLogin": [{"BundleID": "com.example.helper", "Path": "/Users/alice/Downloads/Helper.app", "BackgroundState": 2}],
})
dump("com.apple.spotlight.Shortcuts", {
    "terminal": {"DISPLAY_NAME": "Terminal", "LAST_USED": datetime.datetime(2023, 11, 14, 10, 0, 0),
                 "URL": "file:///System/Applications/Utilities/Terminal.app"},
    "pass": {"DISPLAY_NAME": "Passwords", "LAST_USED": datetime.datetime(2023, 11, 15, 11, 0, 0), "URL": "x-apple.systempreferences:"},
})
