#!/usr/bin/env python3
"""Writes synthetic system-state property lists (receipt, configuration profiles, firewall,
Bluetooth, Time Machine, lockdown pairing). Example data only; the keys and certificates in the
lockdown file are planted markers, not real material. Run: python3 generate.py"""
import datetime as dt, os, plistlib
here = os.path.dirname(os.path.abspath(__file__))


def dump(name, obj, fmt=plistlib.FMT_BINARY):
    with open(os.path.join(here, name), "wb") as f:
        plistlib.dump(obj, f, fmt=fmt)


dump("receipt.plist", {"PackageIdentifier": "com.example.pkg", "PackageVersion": "1.2.3",
                       "InstallDate": dt.datetime(2023, 11, 14, 10, 0, 0), "InstallPrefixPath": "/",
                       "InstallProcessName": "installer"}, plistlib.FMT_XML)
dump("ConfigProfiles.binary", {"_computerLevel": [
    {"ProfileIdentifier": "com.example.profile", "ProfileDisplayName": "Example Wi-Fi and CA", "ProfileOrganization": "Example Org",
     "ProfileUUID": "AAAAAAAA-0000-0000-0000-000000000001", "ProfileInstallDate": dt.datetime(2023, 11, 1, 9, 0, 0),
     "ProfileItems": [{"PayloadType": "com.apple.security.root", "PayloadContent": b"PLANTED-CERT-CONTENT"},
                      {"PayloadType": "com.apple.wifi.managed", "PayloadContent": {"Password": "PLANTED-CERT-CONTENT"}}]}]})
dump("com.apple.alf.plist", {"globalstate": 1, "stealthenabled": 0, "loggingenabled": 1,
                              "applications": [{"path": "/Applications/Example.app", "state": 3}],
                              "exceptions": [{"path": "/usr/libexec/sshd-keygen-wrapper", "state": 3}]})
dump("com.apple.Bluetooth.plist", {"DeviceCache": {"aa-bb-cc-dd-ee-ff": {"Name": "Example Keyboard", "Manufacturer": "Example",
        "LastInquiryUpdate": dt.datetime(2023, 11, 14, 9, 0, 0), "LastNameUpdate": dt.datetime(2023, 11, 10, 9, 0, 0)}},
        "CoreBluetoothCache": {"UUID-1": {"DeviceName": "Example Speaker", "LastSeenTime": dt.datetime(2023, 11, 12, 8, 0, 0)}}})
dump("com.apple.TimeMachine.plist", {"Destinations": [{"DestinationID": "DEST-1", "LastKnownVolumeName": "Backup",
        "SnapshotDates": [dt.datetime(2023, 11, 14, 1, 0, 0), dt.datetime(2023, 11, 13, 1, 0, 0)]}]})
dump("lockdown.plist", {"HostID": "11111111-2222-3333-4444-555555555555", "SystemBUID": "66666666-7777-8888-9999-000000000000",
                        "WiFiMACAddress": "02:00:00:00:00:09", "HostPrivateKey": b"PLANTED-PRIVATE-KEY",
                        "RootPrivateKey": b"PLANTED-PRIVATE-KEY", "EscrowBag": b"PLANTED-ESCROW",
                        "DeviceCertificate": b"PLANTED-CERT", "HostCertificate": b"PLANTED-CERT"})
