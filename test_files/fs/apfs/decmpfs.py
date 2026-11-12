"""Rewrites a file as a transparently compressed file with its data in the decmpfs attribute.

usage: decmpfs.py TYPE FILE
  1  stored after the 16-byte header
  3  zlib stream after the header
  9  stored after the header and a 0xcc marker byte

The data fork is truncated and UF_COMPRESSED set; the kernel then decompresses on read, so
reading the file back through the mount checks the layout.
"""
import ctypes
import os
import stat
import struct
import sys
import zlib

XATTR_SHOWCOMPRESSION = 0x0020
libc = ctypes.CDLL(None, use_errno=True)
libc.setxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]

kind, path = int(sys.argv[1]), sys.argv[2]
data = open(path, "rb").read()
payload = {1: data, 3: zlib.compress(data, 9), 9: b"\xcc" + data}[kind]
value = b"fpmc" + struct.pack("<IQ", kind, len(data)) + payload
if libc.setxattr(path.encode(), b"com.apple.decmpfs", value, len(value), 0, XATTR_SHOWCOMPRESSION) != 0:
    raise OSError(ctypes.get_errno(), "setxattr com.apple.decmpfs")
os.truncate(path, 0)
os.chflags(path, os.stat(path).st_flags | stat.UF_COMPRESSED)
