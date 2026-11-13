Info.plist: a minimal bundle Info.plist (example identifiers only), written with Python's plistlib:
  python3 -c "import plistlib;plistlib.dump({'CFBundleIdentifier':'com.example.evil','CFBundleName':'Evil','CFBundleExecutable':'Evil','CFBundleShortVersionString':'1.0'},open('Info.plist','wb'),fmt=plistlib.FMT_XML)"
