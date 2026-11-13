#!/bin/bash
# Builds the k3s evidence: a real k3s server in a privileged container, a scripted workload, then
# the node's files copied out and the cluster's own listings recorded as truth.
# Usage: build-k3s.sh <output-dir>      (needs docker, openssl; arm64 here, any platform works)
set -euo pipefail
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
C=l8s-k3s
PLATFORM=${PLATFORM:-linux/arm64}
docker rm -f $C >/dev/null 2>&1 || true
docker run -d --name $C --privileged --platform "$PLATFORM" \
  -v "$HERE/audit-policy.yaml:/etc/audit-policy.yaml:ro" rancher/k3s:latest server \
  --write-kubeconfig-mode 644 --disable traefik --disable metrics-server \
  --kube-apiserver-arg=audit-policy-file=/etc/audit-policy.yaml \
  --kube-apiserver-arg=audit-log-path=/var/lib/rancher/k3s/server/logs/audit.log >/dev/null
k() { docker exec -i $C kubectl "$@"; }
for i in $(seq 1 90); do k get nodes 2>/dev/null | grep -q ' Ready' && break; sleep 2; done
k wait --for=condition=Ready node --all --timeout=120s >/dev/null
for i in $(seq 1 60); do k get serviceaccount default >/dev/null 2>&1 && break; sleep 2; done
# Not stock: an auto-applied manifest and a static pod.
docker exec -i $C sh -c 'cat > /var/lib/rancher/k3s/server/manifests/extra-tools.yaml' <<'Y'
apiVersion: v1
kind: Namespace
metadata:
  name: tools
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-helper
  namespace: tools
spec:
  selector:
    matchLabels: {app: node-helper}
  template:
    metadata:
      labels: {app: node-helper}
    spec:
      hostPID: true
      hostNetwork: true
      containers:
        - name: helper
          image: busybox:1.37
          command: ["sh", "-c", "while true; do echo helper-alive; sleep 20; done"]
          securityContext:
            privileged: true
          volumeMounts:
            - name: host
              mountPath: /host
      volumes:
        - name: host
          hostPath:
            path: /
Y
docker exec -i $C sh -c 'mkdir -p /var/lib/rancher/k3s/agent/pod-manifests && cat > /var/lib/rancher/k3s/agent/pod-manifests/static-web.yaml' <<'Y'
apiVersion: v1
kind: Pod
metadata:
  name: static-web
  namespace: kube-system
spec:
  hostNetwork: true
  containers:
    - name: web
      image: nginx:1.27-alpine
      args: ["nginx", "-g", "daemon off;"]
      volumeMounts:
        - {name: sock, mountPath: /var/run/docker.sock}
  volumes:
    - name: sock
      hostPath: {path: /var/run/docker.sock}
Y
# A non-system user (client certificate signed by the cluster's client CA).
docker cp $C:/var/lib/rancher/k3s/server/tls/client-ca.crt "$OUT/client-ca.crt"
docker cp $C:/var/lib/rancher/k3s/server/tls/client-ca.key "$OUT/client-ca.key"
openssl genrsa -out "$OUT/alice.key" 2048 2>/dev/null
openssl req -new -key "$OUT/alice.key" -subj "/CN=alice/O=devs" -out "$OUT/alice.csr"
openssl x509 -req -in "$OUT/alice.csr" -CA "$OUT/client-ca.crt" -CAkey "$OUT/client-ca.key" -CAcreateserial -days 30 -out "$OUT/alice.crt" 2>/dev/null
docker cp "$OUT/alice.crt" $C:/tmp/alice.crt; docker cp "$OUT/alice.key" $C:/tmp/alice.key
ka() { docker exec -i -e KUBECONFIG=/tmp/none $C kubectl --server https://127.0.0.1:6443 --certificate-authority /var/lib/rancher/k3s/server/tls/server-ca.crt --client-certificate /tmp/alice.crt --client-key /tmp/alice.key "$@"; }
k create namespace dev
k create rolebinding alice-admin --clusterrole=admin --group=devs -n dev
# The workload.
k create deployment web --image=nginx:1.27-alpine --replicas=2
k run execer --image=busybox:1.37 --restart=Never -- sleep 3600
k apply -f - < "$HERE/workload.yaml"
k wait --for=condition=Ready pod/execer pod/priv-host pod/secret-user --timeout=240s
k exec execer -- sh -c 'id; echo exec-marker; cat /etc/os-release | head -2' > /dev/null
echo "kubectl-cp-payload" > "$OUT/payload.txt"
docker cp "$OUT/payload.txt" $C:/tmp/payload.txt
k cp /tmp/payload.txt default/execer:/tmp/payload.txt
k cp default/execer:/tmp/payload.txt /tmp/payload-back.txt
k get secret db-pass -o yaml >/dev/null
k run doomed --image=busybox:1.37 --restart=Never -- sh -c 'echo doomed-pod-ran; sleep 600'
k wait --for=condition=Ready pod/doomed --timeout=120s
k delete pod doomed --wait=true
ka create namespace nope 2>/dev/null || true
ka run alice-pod -n dev --image=busybox:1.37 --restart=Never -- sleep 600
ka create rolebinding bob-view --clusterrole=view --user=bob -n dev
ka delete pod alice-pod -n dev
kan() { docker exec -i -e KUBECONFIG=/tmp/none $C kubectl --server https://127.0.0.1:6443 --insecure-skip-tls-verify "$@"; }
kan get --raw /version </dev/null >/dev/null 2>&1 || true; kan get --raw /api/v1/namespaces/default/secrets </dev/null >/dev/null 2>&1 || true
# Wait for the CronJob to have run, a failed pull to be recorded.
for i in $(seq 1 40); do k get jobs -o name 2>/dev/null | grep -q . && break; sleep 5; done
sleep 20
# Truth, recorded while the cluster is up.
mkdir -p "$OUT/truth"
k get pods -A -o json > "$OUT/truth/kubectl-pods.json"
k get events -A -o json > "$OUT/truth/kubectl-events.json"
docker exec $C crictl --runtime-endpoint unix:///run/k3s/containerd/containerd.sock ps -a -o json > "$OUT/truth/crictl-ps.json"
docker exec $C crictl --runtime-endpoint unix:///run/k3s/containerd/containerd.sock pods -o json > "$OUT/truth/crictl-pods.json"
docker exec $C crictl --runtime-endpoint unix:///run/k3s/containerd/containerd.sock images -o json > "$OUT/truth/crictl-images.json"
docker exec $C ctr --address /run/k3s/containerd/containerd.sock -n k8s.io containers ls > "$OUT/truth/ctr-containers.txt"
docker exec $C ctr --address /run/k3s/containerd/containerd.sock -n k8s.io containers ls -q > "$OUT/truth/ctr-containers-ids.txt"
docker exec $C cat /var/lib/rancher/k3s/server/logs/audit.log > "$OUT/truth/audit.log"
docker exec $C k3s --version > "$OUT/truth/version.txt"
docker stop -t 20 $C >/dev/null
# Evidence: the node's files. (Docker volumes are not in `docker export`, hence docker cp.)
EV="$OUT/node"; rm -rf "$EV"; mkdir -p "$EV/var/lib/rancher/k3s/agent" "$EV/var/lib/rancher/k3s/server" "$EV/var/lib/kubelet" "$EV/etc/rancher" "$EV/etc" "$EV/var/log"
for p in var/log/pods var/log/containers etc/rancher/k3s etc/cni var/lib/rancher/k3s/server/manifests var/lib/rancher/k3s/server/logs var/lib/rancher/k3s/agent/pod-manifests var/lib/rancher/k3s/agent/etc var/lib/rancher/k3s/agent/kubelet.kubeconfig var/lib/rancher/k3s/agent/kubeproxy.kubeconfig var/lib/rancher/k3s/agent/client-kubelet.crt; do
  mkdir -p "$EV/$(dirname $p)"; docker cp -L $C:/$p "$EV/$p" 2>/dev/null || docker cp $C:/$p "$EV/$p" || true
done
mkdir -p "$EV/var/lib/rancher/k3s/agent/containerd/io.containerd.metadata.v1.bolt"
docker cp $C:/var/lib/rancher/k3s/agent/containerd/io.containerd.metadata.v1.bolt/meta.db "$EV/var/lib/rancher/k3s/agent/containerd/io.containerd.metadata.v1.bolt/meta.db"
date +%s > "$OUT/truth/taken-at.txt"
docker rm -f $C >/dev/null
echo done
