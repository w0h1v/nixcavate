#!/usr/bin/env python3
"""Builds a synthetic power log shaped like the tables APOLLO's powerlog modules read.
Example data only; nothing comes from a real machine. Run: python3 generate.py"""
import gzip, os, sqlite3

here = os.path.dirname(os.path.abspath(__file__))
path = os.path.join(here, "CurrentPowerlog.PLSQL")
if os.path.exists(path):
    os.remove(path)
db = sqlite3.connect(path)
db.executescript("""
CREATE TABLE PLStorageOperator_EventForward_TimeOffset (ID INTEGER PRIMARY KEY, timestamp REAL, system REAL);
CREATE TABLE PLApplicationAgent_EventForward_Application (ID INTEGER PRIMARY KEY, timestamp REAL, BundleID TEXT, State INTEGER, Pid INTEGER);
CREATE TABLE PLAppTimeService_Aggregate_AppRunTime (ID INTEGER PRIMARY KEY, timestamp REAL, BundleID TEXT, ScreenOnTime REAL, BackgroundTime REAL);
CREATE TABLE PLApplicationAgent_EventNone_AllApps (ID INTEGER PRIMARY KEY, timestamp REAL, BundleIdentifier TEXT, AppName TEXT, AppType TEXT);
CREATE TABLE PLProcessNetworkAgent_Interval_Usage (ID INTEGER PRIMARY KEY, timestamp REAL, ProcessName TEXT, WifiIn REAL, WifiOut REAL, WiredIn REAL, WiredOut REAL);
CREATE TABLE PLSleepWakeAgent_EventForward_PowerState (ID INTEGER PRIMARY KEY, timestamp REAL, State INTEGER, Reason TEXT);
CREATE TABLE PLBatteryAgent_EventBackward_Battery (ID INTEGER PRIMARY KEY, timestamp REAL, Level REAL, IsCharging INTEGER, CycleCount INTEGER);
CREATE TABLE PLWifiAgent_EventForward_Wifi (ID INTEGER PRIMARY KEY, timestamp REAL, SSID TEXT, RSSI INTEGER);
CREATE TABLE PLDisplayAgent_EventForward_Display (ID INTEGER PRIMARY KEY, timestamp REAL, Active INTEGER, Blob BLOB);
CREATE TABLE PLUnrelatedAgent_EventNone_Other (ID INTEGER PRIMARY KEY, timestamp REAL, Secret TEXT);
""")
q = db.execute
q("INSERT INTO PLStorageOperator_EventForward_TimeOffset (timestamp, system) VALUES (1700000000.0, 0.0)")
q("INSERT INTO PLStorageOperator_EventForward_TimeOffset (timestamp, system) VALUES (1700001000.0, 12.5)")
q("INSERT INTO PLApplicationAgent_EventForward_Application (timestamp, BundleID, State, Pid) VALUES (1700000100.0, 'com.example.app', 1, 501)")
q("INSERT INTO PLApplicationAgent_EventForward_Application (timestamp, BundleID, State, Pid) VALUES (1700001100.0, 'com.example.app', 0, 501)")
q("INSERT INTO PLAppTimeService_Aggregate_AppRunTime (timestamp, BundleID, ScreenOnTime, BackgroundTime) VALUES (1700002000.0, 'com.example.editor', 3600.0, 120.0)")
q("INSERT INTO PLApplicationAgent_EventNone_AllApps (timestamp, BundleIdentifier, AppName, AppType) VALUES (1700003000.0, 'com.example.tool', 'Tool', 'User')")
q("INSERT INTO PLProcessNetworkAgent_Interval_Usage (timestamp, ProcessName, WifiIn, WifiOut, WiredIn, WiredOut) VALUES (1700004000.0, 'curl', 1024.0, 2048.0, 0.0, 0.0)")
q("INSERT INTO PLSleepWakeAgent_EventForward_PowerState (timestamp, State, Reason) VALUES (1700005000.0, 3, 'Lid Open')")
q("INSERT INTO PLBatteryAgent_EventBackward_Battery (timestamp, Level, IsCharging, CycleCount) VALUES (1700006000.0, 87.0, 1, 212)")
q("INSERT INTO PLWifiAgent_EventForward_Wifi (timestamp, SSID, RSSI) VALUES (1700007000.0, 'ExampleNet', -55)")
q("INSERT INTO PLDisplayAgent_EventForward_Display (timestamp, Active, Blob) VALUES (1700008000.0, 1, x'00010203')")
q("INSERT INTO PLDisplayAgent_EventForward_Display (timestamp, Active) VALUES (1e300, 0)")
q("INSERT INTO PLUnrelatedAgent_EventNone_Other (timestamp, Secret) VALUES (1700009000.0, 'planted-secret-not-read')")
db.commit()
db.close()

# An archive holds the same schema, gzip-compressed.
with open(path, "rb") as f, open(os.path.join(here, "powerlog_2024_01_01.PLSQL.gz"), "wb") as out:
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as g:
        g.write(f.read())
