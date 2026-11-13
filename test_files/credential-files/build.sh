#!/bin/bash
# Creates credential files with the real tools in a throwaway arm64 container (aws, kubectl,
# npm, git, vault, docker) for example accounts, plus the files whose tools need a vendor login
# (gcloud, az, terraform, oci) written to the documented format. Every secret is a PLANTED-*
# string so a test can assert none reaches the output.
# Usage: build.sh <output-dir>
set -uo pipefail
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
docker rm -f l8s-cred l8s-registry >/dev/null 2>&1
mkdir -p "$OUT/auth"
docker run --rm --platform linux/arm64 httpd:2.4 htpasswd -Bbn alice PLANTED-REGISTRY-PASSWORD-0007 > "$OUT/auth/htpasswd"
docker run -d --name l8s-registry --platform linux/arm64 -p 5055:5000 -v "$OUT/auth:/auth:ro" \
  -e REGISTRY_AUTH=htpasswd -e REGISTRY_AUTH_HTPASSWD_REALM=r -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd registry:2 >/dev/null
docker run -d --name l8s-cred --platform linux/arm64 -v /var/run/docker.sock:/var/run/docker.sock debian:12 sleep 3600 >/dev/null
x() { docker exec -i l8s-cred bash -c "$1"; }
x 'apt-get update -qq && apt-get install -y -qq curl ca-certificates awscli git npm unzip docker.io >/dev/null 2>&1; echo apt-done'
x 'curl -sL -o /usr/local/bin/kubectl https://dl.k8s.io/release/$(curl -sL https://dl.k8s.io/release/stable.txt)/bin/linux/arm64/kubectl && chmod +x /usr/local/bin/kubectl && kubectl version --client | head -1'
x 'V=$(curl -s https://releases.hashicorp.com/vault/ | grep -o "vault_[0-9.]*" | head -1 | cut -d_ -f2); curl -sL -o /tmp/v.zip https://releases.hashicorp.com/vault/${V}/vault_${V}_linux_arm64.zip && unzip -qo /tmp/v.zip -d /usr/local/bin && vault version'
x 'mkdir -p /home/alice && useradd -d /home/alice alice 2>/dev/null; chown alice /home/alice; true'
as() { docker exec -i -u alice -e HOME=/home/alice l8s-cred bash -c "$1"; }
as 'aws configure set aws_access_key_id AKIAEXAMPLEPLANTED01 && aws configure set aws_secret_access_key PLANTED-AWS-SECRET-0008 && aws configure set region eu-west-1
aws configure set aws_access_key_id AKIAEXAMPLEPLANTED02 --profile prod && aws configure set aws_secret_access_key PLANTED-AWS-SECRET-0009 --profile prod && aws configure set region us-east-1 --profile prod
aws configure set role_arn arn:aws:iam::123456789012:role/Admin --profile assume; aws configure set source_profile prod --profile assume
aws configure list-profiles' > "$OUT/aws.truth.txt" 2>&1
as 'kubectl config set-cluster demo --server=https://203.0.113.10:6443 --insecure-skip-tls-verify=true && kubectl config set-credentials admin --token=PLANTED-KUBE-TOKEN-0010 && kubectl config set-context demo --cluster=demo --user=admin && kubectl config use-context demo && kubectl config get-contexts' > "$OUT/kube.truth.txt" 2>&1
as 'npm config set //registry.npmjs.org/:_authToken PLANTED-NPM-TOKEN-0011 && npm config set //npm.pkg.example.com/:_authToken PLANTED-NPM-TOKEN-0012 && npm config list' > "$OUT/npm.truth.txt" 2>&1
as 'git config --global credential.helper store && printf "protocol=https\nhost=git.example.com\nusername=alice\npassword=PLANTED-GIT-PASSWORD-0013\n\n" | git credential approve && printf "protocol=https\nhost=github.com\nusername=bob\npassword=PLANTED-GIT-PASSWORD-0014\n\n" | git credential approve' > "$OUT/git.truth.txt" 2>&1
# vault: a dev server in the same container; `vault login` writes ~/.vault-token.
x '(vault server -dev -dev-root-token-id=PLANTED-VAULT-TOKEN-0015 >/tmp/vault.log 2>&1 &) ; sleep 4; true'
as 'VAULT_ADDR=http://127.0.0.1:8200 vault login PLANTED-VAULT-TOKEN-0015 | head -3' > "$OUT/vault.truth.txt" 2>&1
# docker: a real `docker login` against a registry with htpasswd auth.
x 'HOME=/home/alice docker login localhost:5055 -u alice -p PLANTED-REGISTRY-PASSWORD-0007; chown -R alice /home/alice/.docker' > "$OUT/docker.truth.txt" 2>&1
# documented formats (tools need an account or a browser)
as 'mkdir -p ~/.azure ~/.config/gcloud/legacy_credentials/ci@example-project.iam.gserviceaccount.com ~/.config/gcloud/configurations ~/.oci ~/.terraform.d ~/.config/gh
cat > ~/.azure/azureProfile.json <<Y
{"installationId":"00000000-0000-0000-0000-000000000001","subscriptions":[{"id":"11111111-2222-3333-4444-555555555555","name":"Example Subscription","state":"Enabled","user":{"name":"alice@example.com","type":"user"},"isDefault":true,"tenantId":"66666666-7777-8888-9999-000000000000","environmentName":"AzureCloud"}]}
Y
echo "{\"PLANTED\":\"PLANTED-AZURE-TOKEN-CACHE-0016\"}" > ~/.azure/msal_token_cache.json
cat > ~/.config/gcloud/configurations/config_default <<Y
[core]
account = alice@example.com
project = example-project

[compute]
region = europe-west1
Y
echo "{\"type\":\"service_account\",\"client_email\":\"ci@example-project.iam.gserviceaccount.com\",\"private_key\":\"PLANTED-GCP-PRIVATE-KEY-0017\"}" > ~/.config/gcloud/legacy_credentials/ci@example-project.iam.gserviceaccount.com/adc.json
python3 -c "print(1)" 2>/dev/null; head -c 64 /dev/urandom > ~/.config/gcloud/access_tokens.db
cat > ~/.oci/config <<Y
[DEFAULT]
user=ocid1.user.oc1..exampleuser
fingerprint=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99
key_file=~/.oci/oci_api_key.pem
tenancy=ocid1.tenancy.oc1..exampletenancy
region=us-ashburn-1
Y
echo PLANTED-OCI-KEY-0018 > ~/.oci/oci_api_key.pem
cat > ~/.terraform.d/credentials.tfrc.json <<Y
{"credentials":{"app.terraform.io":{"token":"PLANTED-TFE-TOKEN-0019"},"tfe.example.com":{"token":"PLANTED-TFE-TOKEN-0020"}}}
Y
cat > ~/.netrc <<Y
machine ftp.example.com login alice password PLANTED-NETRC-PASSWORD-0021
machine api.example.com
  login bob
  password PLANTED-NETRC-PASSWORD-0022
default login anonymous password guest@
Y
cat > ~/.pypirc <<Y
[distutils]
index-servers =
    pypi
    internal

[pypi]
username = __token__
password = PLANTED-PYPI-TOKEN-0023

[internal]
repository = https://pypi.example.com/simple
username = alice
password = PLANTED-PYPI-PASSWORD-0024
Y
cat > ~/.config/gh/hosts.yml <<Y
github.com:
    user: alice
    oauth_token: PLANTED-GH-TOKEN-0025
    git_protocol: https
Y
chmod 600 ~/.netrc ~/.pypirc ~/.git-credentials 2>/dev/null; ls -la ~ '
rm -rf "$OUT/tree"; mkdir -p "$OUT/tree/home"
docker cp l8s-cred:/home/alice "$OUT/tree/home/alice"
docker rm -f l8s-cred l8s-registry >/dev/null
echo done
