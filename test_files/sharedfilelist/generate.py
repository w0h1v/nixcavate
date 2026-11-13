#!/usr/bin/env python3
"""Builds Example.sfl2: an NSKeyedArchiver archive shaped like a shared file list, holding
synthetic bookmark data written from the documented bookmark layout (little-endian header,
typed items, one table of contents). Example data only. Run: python3 generate.py"""
import os, plistlib, struct

here = os.path.dirname(os.path.abspath(__file__))


def item_text(s):
    b = s.encode()
    return struct.pack("<II", len(b), 0x0101) + b


def item_number(n):
    return struct.pack("<IIq", 8, 0x0304, n)


def item_date(secs):
    return struct.pack("<II", 8, 0x0400) + struct.pack(">d", secs)


def bookmark(path_parts, volume, created, volume_path="/"):
    entries = []  # (key, encoded)
    area = bytearray(4)  # first TOC offset

    def add(encoded):
        off = len(area)
        area.extend(encoded)
        while len(area) % 4:
            area.append(0)
        return off

    part_offsets = [add(item_text(p)) for p in path_parts]
    array = struct.pack("<II", 4 * len(part_offsets), 0x0601) + b"".join(struct.pack("<I", o) for o in part_offsets)
    entries.append((0x1004, add(array)))
    entries.append((0x2002, add(item_text(volume_path))))
    entries.append((0x2010, add(item_text(volume))))
    entries.append((0x1040, add(item_date(created))))
    toc_off = len(area)
    struct.pack_into("<I", area, 0, toc_off)
    area.extend(struct.pack("<IIIII", 12 * len(entries) + 12, 0xFFFFFFFE, 1, 0, len(entries)))
    for key, off in entries:
        area.extend(struct.pack("<III", key, off, 0))
    header = 48
    out = b"book" + struct.pack("<III", header + len(area), 0x10040000, header)
    out = out.ljust(header, b"\0") + bytes(area)
    return out


class Archive:
    def __init__(self):
        self.objects = ["$null"]

    def add(self, obj):
        self.objects.append(obj)
        return plistlib.UID(len(self.objects) - 1)

    def cls(self, name):
        return self.add({"$classname": name, "$classes": [name, "NSObject"]})

    def string(self, s):
        return self.add(s)

    def dictionary(self, mapping):
        keys = [self.string(k) for k in mapping]
        values = [v if isinstance(v, plistlib.UID) else self.add(v) for v in mapping.values()]
        return self.add({"NS.keys": keys, "NS.objects": values, "$class": self.cls("NSDictionary")})

    def array(self, uids):
        return self.add({"NS.objects": uids, "$class": self.cls("NSArray")})

    def data(self, b):
        return self.add({"NS.data": b, "$class": self.cls("NSData")})


a = Archive()
root_slot = a.add(None)  # reserve index 1 for the root
mk = lambda name, parts, vol, order, vpath="/": a.add({
    "$class": a.cls("SFLListItem"),
    "Name": a.string(name),
    "Bookmark": a.data(bookmark(parts, vol, 700000000.0, vpath)),
    "order": order,
    "visibility": 0,
    "uuid": a.string("11111111-2222-3333-4444-55555555555%d" % order),
})
items = a.array([
    mk("notes.txt", ["Users", "alice", "Documents", "notes.txt"], "Macintosh HD", 0),
    mk("report.pdf", ["report.pdf"], "Backup", 1, "/Volumes/Backup"),
    a.add({"$class": a.cls("SFLListItem"), "Name": a.string("no-bookmark"), "order": 2}),
    a.add({"$class": a.cls("SFLListItem"), "Name": a.string("bad-bookmark"), "Bookmark": a.data(b"not a bookmark"), "order": 3}),
])
root = a.dictionary({"items": items, "properties": a.dictionary({"com.apple.LSSharedFileList.MaxAmount": 10})})
a.objects[root_slot.data] = a.objects[root.data]
doc = {"$archiver": "NSKeyedArchiver", "$version": 100000, "$top": {"root": root_slot}, "$objects": a.objects}
with open(os.path.join(here, "Example.sfl2"), "wb") as f:
    plistlib.dump(doc, f, fmt=plistlib.FMT_BINARY)

# Hostile archives: an object that refers to itself, and a chain whose references double at
# every level (2**40 expansions if followed naively).
def archive_doc(objects):
    return {"$archiver": "NSKeyedArchiver", "$version": 100000, "$top": {"root": plistlib.UID(1)}, "$objects": objects}


with open(os.path.join(here, "Cycle.plist"), "wb") as f:
    plistlib.dump(archive_doc(["$null", {"$class": plistlib.UID(2), "me": plistlib.UID(1)},
                               {"$classname": "Loop", "$classes": ["Loop"]}]), f, fmt=plistlib.FMT_BINARY)
bomb = ["$null"]
depth = 40
for level in range(depth):
    child = plistlib.UID(level + 2)
    bomb.append({"$class": plistlib.UID(depth + 1), "a": child, "b": child})
bomb.append("leaf")
bomb.insert(depth + 1, {"$classname": "Bomb", "$classes": ["Bomb"]})
with open(os.path.join(here, "Bomb.plist"), "wb") as f:
    plistlib.dump(archive_doc(bomb), f, fmt=plistlib.FMT_BINARY)
