#!/bin/bash
# Files of tools that need a remote peer or an account to produce them, written in the formats
# their documentation and published forensic write-ups describe. Example data only.
# See docs/LIMITATIONS.md, "Synthetic only".
set -euo pipefail
cd "$(dirname "$0")"; rm -rf synthetic; mkdir -p synthetic; cd synthetic
mkdir -p home/alice/.vscode-server/cli/servers/Stable-0123 etc/anydesk var/log/teamviewer15 usr/local/mesh_services/meshagent home/alice/.vscode/cli root/.config/rustdesk var/log
printf 'Incoming    2026-11-12, 14:03    User    7283745112    1000000001\nOutgoing    2026-11-12, 15:20    User    1122334455    1000000001\nIncoming    2026-11-12, 23:59    Accept    5566778899    1000000001\n' > etc/anydesk/connection_trace.txt
printf '1234567890\tJohn Doe\t12-11-2026 14:03:11\t12-11-2026 14:21:45\talice\tRemoteControl\t{00000000-0000-0000-0000-000000000001}\n987654321\tHelpdesk\t13-11-2026 09:00:00\t13-11-2026 09:05:30\troot\tFileTransfer\t{00000000-0000-0000-0000-000000000002}\n' > var/log/teamviewer15/Connections_incoming.txt
cat > usr/local/mesh_services/meshagent/meshagent.msh <<Y
MeshName=Example Mesh
MeshType=2
MeshID=0xAABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899
ServerID=00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
MeshServer=wss://mesh.example.com:443/agent.ashx
Y
echo '{"name":"alice-box","id":"abcd1234ef","cluster":"euw"}' > home/alice/.vscode/cli/code_tunnel.json
cat > root/.config/rustdesk/RustDesk2.toml <<Y
rendezvous_server = 'rd.example.com:21116'
nat_type = 1
serial = 0

[options]
custom-rendezvous-server = 'rd.example.com'
relay-server = 'rd.example.com'
key = 'EXAMPLE-RUSTDESK-SERVER-PUBLIC-KEY'
Y
printf '[2026-11-13 01:19:08] info Using GitHub for authentication, run `code tunnel user login --provider <provider>` option to change this.\n[2026-11-13 01:19:09] info tunnel alice-box started\n' > home/alice/.vscode-server/cli/servers/Stable-0123/log.txt
cat > var/log/openvpn-classic.log <<Y
Fri Nov 13 01:30:29 2026 OpenVPN 2.6.3 aarch64-unknown-linux-gnu
Fri Nov 13 01:30:30 2026 us=1234 TCP/UDP: Preserving recently used remote address: [AF_INET]203.0.113.5:1194
Fri Nov 13 01:30:31 2026 Peer Connection Initiated with [AF_INET]203.0.113.5:1194
Fri Nov 13 01:30:32 2026 Initialization Sequence Completed
Y
