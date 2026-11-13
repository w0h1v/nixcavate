#!/usr/bin/env python3
"""pamtry SERVICE USER PASSWORD [rhost=HOST|tty=NAME]: one pam_authenticate() through libpam."""
import ctypes, ctypes.util, sys

PAM_RHOST, PAM_TTY = 4, 3
PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON = 1, 2

class Message(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]

class Response(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_char_p), ("resp_retcode", ctypes.c_int)]

CONV = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(Message)),
                        ctypes.POINTER(ctypes.POINTER(Response)), ctypes.c_void_p)
libc = ctypes.CDLL(ctypes.util.find_library("c"))
libc.calloc.restype = ctypes.c_void_p
libc.strdup.restype = ctypes.c_void_p
libpam = ctypes.CDLL(ctypes.util.find_library("pam") or "libpam.so.0")
libpam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]

service, user, password = sys.argv[1:4]
source = sys.argv[4] if len(sys.argv) > 4 else ""

def converse(n, messages, responses, _data):
    array = libc.calloc(n, ctypes.sizeof(Response))
    responses[0] = ctypes.cast(array, ctypes.POINTER(Response))
    for i in range(n):
        if messages[i][0].msg_style in (PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON):
            responses[0][i].resp = ctypes.cast(libc.strdup(password.encode()), ctypes.c_char_p)
    return 0

class Conv(ctypes.Structure):
    _fields_ = [("conv", CONV), ("data", ctypes.c_void_p)]

callback = CONV(converse)
conv = Conv(callback, None)
handle = ctypes.c_void_p()
rc = libpam.pam_start(service.encode(), user.encode(), ctypes.byref(conv), ctypes.byref(handle))
if source.startswith("rhost="):
    libpam.pam_set_item(handle, PAM_RHOST, source[6:].encode())
elif source.startswith("tty="):
    libpam.pam_set_item(handle, PAM_TTY, source[4:].encode())
rc = libpam.pam_authenticate(handle, 0)
if rc == 0:
    libpam.pam_acct_mgmt(handle, 0)
print("%s %s: %s" % (user, source or "-", "ok" if rc == 0 else "rc=%d" % rc))
libpam.pam_end(handle, rc)
