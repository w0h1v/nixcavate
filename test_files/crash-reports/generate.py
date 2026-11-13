#!/usr/bin/env python3
"""Writes synthetic crash reports shaped like the published .ips / .crash / .panic layouts.
Example data only. Run: python3 generate.py"""
import json, os
here = os.path.dirname(os.path.abspath(__file__))

header = {"app_name": "Example", "timestamp": "2023-11-14 10:00:00.00 -0800", "app_version": "1.2", "bug_type": "309",
          "os_version": "macOS 14.1 (23B74)", "incident_id": "11111111-2222-3333-4444-555555555555", "name": "Example",
          "bundleID": "com.example.app"}
body = {"captureTime": "2023-11-14 10:00:00.1234 -0800", "pid": 4242, "procName": "Example",
        "procPath": "/Applications/Example.app/Contents/MacOS/Example",
        "bundleInfo": {"CFBundleShortVersionString": "1.2", "CFBundleIdentifier": "com.example.app"},
        "parentProc": "launchd", "parentPid": 1, "responsibleProc": "Example", "codeSigningID": "com.example.app",
        "codeSigningTeamID": "EXAMPLE123", "translated": True,
        "exception": {"type": "EXC_BAD_ACCESS", "signal": "SIGSEGV", "subtype": "KERN_INVALID_ADDRESS at 0x0"},
        "termination": {"namespace": "SIGNAL", "indicator": "Segmentation fault: 11"},
        "faultingThread": 1,
        "threads": [{"state": "PLANTED-THREAD-DUMP-STATE", "frames": []},
                    {"frames": [{"imageIndex": 0, "symbol": "main"}, {"imageIndex": 1, "symbol": "abort"}, {"imageIndex": 9}]}],
        "usedImages": [{"name": "Example"}, {"name": "libsystem_c.dylib"}]}
with open(os.path.join(here, "Example.ips"), "w") as f:
    f.write(json.dumps(header) + "\n" + json.dumps(body))

with open(os.path.join(here, "Old.crash"), "w") as f:
    f.write("""Process:               OldTool [321]
Path:                  /usr/local/bin/OldTool
Identifier:            com.example.oldtool
Version:               3.0 (30)
Code Type:             X86-64 (Native)
Parent Process:        launchd [1]
Responsible:           Terminal [100]
User ID:               501

Date/Time:             2019-01-01 12:30:45.123 +0100
OS Version:            Mac OS X 10.14.2 (18C54)

Exception Type:        EXC_CRASH (SIGABRT)
Exception Codes:       0x0000000000000000, 0x0000000000000000
Crashed Thread:        0  Dispatch queue: com.apple.main-thread

Thread 0 Crashed:: Dispatch queue: com.apple.main-thread
0   libsystem_kernel.dylib        	0x00007fff6e0e0b66 __pthread_kill + 10
""")

with open(os.path.join(here, "Kernel.panic"), "w") as f:
    f.write("""panic(cpu 2 caller 0xffffff8000b0c2d3): "Example kernel panic string"@/path/example.c:123
Backtrace (CPU 2), Frame : Return Address (4 potential args on stack)

BSD process name corresponding to current thread: kernel_task
Mac OS version:
18C54

Kernel version:
Darwin Kernel Version 18.2.0: Thu Dec 20 20:46:53 PST 2018; root:xnu-4903.241.1~1/RELEASE_X86_64
""")
