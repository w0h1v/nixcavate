#!/usr/bin/env python3
"""Builds a synthetic netusage.sqlite (Core Data layout as read by APOLLO's netusage module),
a DHCP lease and a NetworkInterfaces.plist. Example data only. Run: python3 generate.py"""
import os, plistlib, sqlite3, datetime
here = os.path.dirname(os.path.abspath(__file__))
path = os.path.join(here, "netusage.sqlite")
if os.path.exists(path):
    os.remove(path)
db = sqlite3.connect(path)
db.executescript("""
CREATE TABLE ZPROCESS (Z_PK INTEGER PRIMARY KEY, ZPROCNAME VARCHAR, ZBUNDLENAME VARCHAR, ZFIRSTTIMESTAMP TIMESTAMP, ZTIMESTAMP TIMESTAMP);
CREATE TABLE ZLIVEUSAGE (Z_PK INTEGER PRIMARY KEY, ZHASPROCESS INTEGER, ZTIMESTAMP TIMESTAMP, ZWIFIIN FLOAT, ZWIFIOUT FLOAT, ZWIREDIN FLOAT, ZWIREDOUT FLOAT, ZWWANIN FLOAT, ZWWANOUT FLOAT);
CREATE TABLE ZNETWORKATTACHMENT (Z_PK INTEGER PRIMARY KEY, ZIDENTIFIER VARCHAR, ZFIRSTTIMESTAMP TIMESTAMP, ZTIMESTAMP TIMESTAMP);
""")
db.execute("INSERT INTO ZPROCESS VALUES (1,'curl',NULL,700000000.0,700003600.0)")
db.execute("INSERT INTO ZPROCESS VALUES (2,'Safari','com.apple.Safari',700000100.0,700003700.0)")
db.execute("INSERT INTO ZLIVEUSAGE VALUES (1,1,700001000.0,1000,50,0,0,0,0)")
db.execute("INSERT INTO ZLIVEUSAGE VALUES (2,2,700002000.0,5000,600,0,0,0,0)")
db.execute("INSERT INTO ZLIVEUSAGE VALUES (3,99,700002500.0,1,1,0,0,0,0)")
db.execute("INSERT INTO ZNETWORKATTACHMENT VALUES (1,'ExampleNet',700000000.0,700003000.0)")
db.commit(); db.close()

lease = {"IPAddress": "192.0.2.10", "LeaseLength": 86400, "LeaseStartDate": datetime.datetime(2023, 11, 14, 10, 0, 0),
         "RouterIPAddress": "192.0.2.1", "RouterHardwareAddress": bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
         "SSID": "ExampleNet", "PacketData": b"planted-dhcp-packet"}
with open(os.path.join(here, "lease.plist"), "wb") as f:
    plistlib.dump(lease, f, fmt=plistlib.FMT_XML)
ifaces = {"Interfaces": [
    {"BSD Name": "en0", "IOMACAddress": bytes([0x02, 0, 0, 0, 0, 1]), "IOBuiltin": True, "IOPrimaryInterface": True,
     "SCNetworkInterfaceType": "IEEE80211", "SCNetworkInterfaceInfo": {"UserDefinedName": "Wi-Fi"}},
    {"BSD Name": "en5", "IOMACAddress": bytes([0x02, 0, 0, 0, 0, 2]), "SCNetworkInterfaceType": "Ethernet",
     "SCNetworkInterfaceInfo": {"UserDefinedName": "USB 10/100/1000 LAN"}}]}
with open(os.path.join(here, "NetworkInterfaces.plist"), "wb") as f:
    plistlib.dump(ifaces, f, fmt=plistlib.FMT_XML)
