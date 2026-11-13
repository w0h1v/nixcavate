#!/bin/bash
# Builds the kubeadm-style evidence: a real `kind` node (kubeadm + kubelet + containerd + static
# pods), the same scripted workload as build-k3s.sh, then the node's files copied out (never
# /etc/kubernetes/pki) and the cluster's own listings recorded as truth.
# Usage: build-kind.sh <kind-binary> <output-dir>
set -euo pipefail
KIND=$1
OUT=$(mkdir -p "$2" && cd "$2" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
N=l8s-control-plane
"$KIND" delete cluster --name l8s >/dev/null 2>&1 || true
sed "s#@POLICY@#$HERE/audit-policy.yaml#" "$HERE/kind-config.yaml" > "$OUT/kind-config.yaml"
"$KIND" create cluster --name l8s --config "$OUT/kind-config.yaml" --kubeconfig "$OUT/kubeconfig" --wait 180s
export KUBECONFIG="$OUT/kubeconfig"
k() { kubectl "$@"; }
for i in $(seq 1 60); do k get serviceaccount default >/dev/null 2>&1 && break; sleep 2; done
# Not stock: a static pod.
docker exec -i $N sh -c 'cat > /etc/kubernetes/manifests/static-web.yaml' <<'Y'
apiVersion: v1
kind: Pod
metadata:
  name: static-web
  namespace: kube-system
spec:
  hostNetwork: true
  hostPID: true
  containers:
    - name: web
      image: busybox:1.37
      command: ["sh", "-c", "while true; do echo static-alive; sleep 20; done"]
      securityContext:
        privileged: true
      volumeMounts:
        - {name: root, mountPath: /host}
  volumes:
    - name: root
      hostPath: {path: /}
Y
docker cp $N:/etc/kubernetes/pki/ca.crt "$OUT/ca.crt"; docker cp $N:/etc/kubernetes/pki/ca.key "$OUT/ca.key"
openssl genrsa -out "$OUT/alice.key" 2048 2>/dev/null
openssl req -new -key "$OUT/alice.key" -subj "/CN=alice/O=devs" -out "$OUT/alice.csr"
openssl x509 -req -in "$OUT/alice.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial -days 30 -out "$OUT/alice.crt" 2>/dev/null
SERVER=$(k config view --minify -o jsonpath='{.clusters[0].cluster.server}')
ka() { KUBECONFIG=/dev/null kubectl --server "$SERVER" --certificate-authority "$OUT/ca.crt" --client-certificate "$OUT/alice.crt" --client-key "$OUT/alice.key" "$@"; }
k create namespace dev
k create rolebinding alice-admin --clusterrole=admin --group=devs -n dev
k create deployment web --image=nginx:1.27-alpine --replicas=2
k run execer --image=busybox:1.37 --restart=Never -- sleep 3600
k apply -f "$HERE/workload.yaml"
k wait --for=condition=Ready pod/execer pod/priv-host pod/secret-user --timeout=300s
k exec execer -- sh -c 'id; echo exec-marker' >/dev/null
echo "kubectl-cp-payload" > "$OUT/payload.txt"
k cp "$OUT/payload.txt" default/execer:/tmp/payload.txt
k cp default/execer:/tmp/payload.txt "$OUT/payload-back.txt"
k get secret db-pass -o yaml >/dev/null
k run doomed --image=busybox:1.37 --restart=Never -- sh -c 'echo doomed-pod-ran; sleep 600'
k wait --for=condition=Ready pod/doomed --timeout=120s
k delete pod doomed --wait=true
ka run alice-pod -n dev --image=busybox:1.37 --restart=Never -- sleep 600
ka create rolebinding bob-view --clusterrole=view --user=bob -n dev
ka delete pod alice-pod -n dev
curl -sk "$SERVER/version" >/dev/null; curl -sk "$SERVER/api/v1/namespaces/default/secrets" >/dev/null || true
for i in $(seq 1 40); do k get jobs -o name 2>/dev/null | grep -q . && break; sleep 5; done
sleep 20
mkdir -p "$OUT/truth"
k get pods -A -o json > "$OUT/truth/kubectl-pods.json"
k get events -A -o json > "$OUT/truth/kubectl-events.json"
docker exec $N crictl ps -a -o json > "$OUT/truth/crictl-ps.json"
docker exec $N crictl pods -o json > "$OUT/truth/crictl-pods.json"
docker exec $N crictl images -o json > "$OUT/truth/crictl-images.json"
docker exec $N ctr -n k8s.io containers ls > "$OUT/truth/ctr-containers.txt"
docker exec $N ctr -n k8s.io containers ls -q > "$OUT/truth/ctr-containers-ids.txt"
docker exec $N cat /var/log/kubernetes/audit/audit.log > "$OUT/truth/audit.log"
k version -o json > "$OUT/truth/version.json"
docker stop -t 20 $N >/dev/null
EV="$OUT/node"; rm -rf "$EV"; mkdir -p "$EV"
for p in var/log/pods var/log/containers var/log/kubernetes etc/cni etc/kubernetes/manifests etc/kubernetes/admin.conf etc/kubernetes/super-admin.conf etc/kubernetes/kubelet.conf etc/kubernetes/controller-manager.conf etc/kubernetes/scheduler.conf var/lib/kubelet/config.yaml var/lib/kubelet/kubeadm-flags.env var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db; do
  mkdir -p "$EV/$(dirname $p)"; docker cp $N:/$p "$EV/$p" || echo "missing $p"
done
date +%s > "$OUT/truth/taken-at.txt"
"$KIND" delete cluster --name l8s
echo done
