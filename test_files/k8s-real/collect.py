#!/usr/bin/env python3
"""Turns the output of build-k3s.sh / build-kind.sh into the small fixtures the tests use.

usage: collect.py <build-output-dir> <k3s|kind> <destination>

- copies the node files the artifacts read (credentials in kubeconfigs are replaced by PLANTED-*
  strings so a test can check they never reach the output);
- shrinks the audit log: request/response bodies removed, cluster components' routine requests cut to 25;
- writes `expected.json`, counted from the clusters' own listings (crictl, kubectl, ctr) and from the
  audit log with plain Python rules that do not share code with the Rust parser.
"""
import base64, gzip, json, os, re, shutil, sys

work, flavor, dest = sys.argv[1:4]
node = os.path.join(work, "node")
truth = os.path.join(work, "truth")
keep = {
    "k3s": [
        "var/log/pods", "var/lib/rancher/k3s/server/manifests", "var/lib/rancher/k3s/agent/pod-manifests",
        "var/lib/rancher/k3s/agent/etc/kubelet.conf.d", "var/lib/rancher/k3s/agent/kubelet.kubeconfig",
        "etc/rancher/k3s/k3s.yaml", "var/lib/rancher/k3s/agent/etc/cni/net.d",
    ],
    "kind": [
        "var/log/pods", "etc/kubernetes/manifests", "var/lib/kubelet/config.yaml", "var/lib/kubelet/kubeadm-flags.env",
        "etc/kubernetes/admin.conf", "etc/kubernetes/kubelet.conf", "etc/kubernetes/scheduler.conf",
        "etc/kubernetes/controller-manager.conf", "etc/cni/net.d",
    ],
}[flavor]
shutil.rmtree(dest, ignore_errors=True)
for rel in keep:
    src = os.path.join(node, rel)
    if not os.path.exists(src):
        print("missing", rel); continue
    dst = os.path.join(dest, "node", rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.isdir(src):
        shutil.copytree(src, dst, symlinks=False)
    else:
        shutil.copy(src, dst)
# Credentials: replace what a kubeconfig embeds.
planted = base64.b64encode(b"PLANTED-KUBE-SECRET-").decode()
for root, _, files in os.walk(os.path.join(dest, "node")):
    for f in files:
        p = os.path.join(root, f)
        if f.endswith((".conf", ".yaml", ".kubeconfig")) and "kubeconfig" in f or f in ("admin.conf", "kubelet.conf", "scheduler.conf", "controller-manager.conf", "k3s.yaml"):
            s = open(p).read()
            s = re.sub(r"(client-key-data|client-certificate-data|token): .*", lambda m: f"{m.group(1)}: {planted}", s)
            open(p, "w").write(s)
# containerd metadata
meta = {"k3s": "var/lib/rancher/k3s/agent/containerd/io.containerd.metadata.v1.bolt/meta.db",
        "kind": "var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"}[flavor]
# The metadata file lives with the containerd-containers fixtures (the fuzz seeds are read from there).
seed_dir = os.path.join(os.path.dirname(os.path.abspath(dest)), "..", "containerd-containers")
os.makedirs(seed_dir, exist_ok=True)
with open(os.path.join(node, meta), "rb") as f, gzip.open(os.path.join(seed_dir, flavor + "-meta.db.gz"), "wb", 9) as g:
    g.write(f.read())
shutil.copy(os.path.join(truth, "ctr-containers.txt"), os.path.join(dest, "ctr-containers.txt"))
shutil.copy(os.path.join(truth, "taken-at.txt"), os.path.join(dest, "taken-at.txt"))

# Audit log
def component(user):
    return any(user.startswith(p) for p in ("system:node:", "system:kube-", "system:apiserver", "system:k3s-", "k3s-", "system:serviceaccount:kube-system:")) or user == "system:node"
audit_in = os.path.join(truth, "audit.log")
lines, routine = [], 0
for raw in open(audit_in):
    e = json.loads(raw)
    e.pop("requestObject", None); e.pop("responseObject", None)
    user = e["user"]["username"]
    anon = user == "system:anonymous" or "system:unauthenticated" in e["user"].get("groups", [])
    if component(user) and not anon:
        routine += 1
        if routine > 25:
            continue
    lines.append(json.dumps(e, separators=(",", ":")))
audit_name = {"k3s": "audit.log", "kind": "audit.log"}[flavor]
open(os.path.join(dest, audit_name), "w").write("\n".join(lines) + "\n")

# expected.json: counted from the clusters' own listings and with plain Python over the audit fixture
exp = {"containers": [], "audit": {}}
ps = json.load(open(os.path.join(truth, "crictl-ps.json")))["containers"]
for c in ps:
    l = c["labels"]
    exp["containers"].append({"id": c["id"], "namespace": l.get("io.kubernetes.pod.namespace"), "pod": l.get("io.kubernetes.pod.name"),
        "uid": l.get("io.kubernetes.pod.uid"), "container": l.get("io.kubernetes.container.name"), "attempt": int(c["metadata"]["attempt"]),
        "image": c["image"]["image"] if "image" in c["image"] else ""})
pods = json.load(open(os.path.join(truth, "crictl-pods.json")))["items"]
exp["sandboxes"] = [{"id": p["id"], "namespace": p["metadata"]["namespace"], "pod": p["metadata"]["name"], "uid": p["metadata"]["uid"]} for p in pods]
kp = json.load(open(os.path.join(truth, "kubectl-pods.json")))["items"]
def pod_facts(p):
    spec = p["spec"]
    cs = spec.get("containers", []) + spec.get("initContainers", [])
    return {"namespace": p["metadata"]["namespace"], "name": p["metadata"]["name"], "images": sorted({c["image"] for c in cs}),
            "hostNetwork": bool(spec.get("hostNetwork")), "hostPID": bool(spec.get("hostPID")),
            "privileged": any((c.get("securityContext") or {}).get("privileged") for c in cs),
            "hostPaths": sorted({v["hostPath"]["path"] for v in spec.get("volumes", []) if "hostPath" in v}),
            "static": any(o.get("kind") == "Node" for o in p["metadata"].get("ownerReferences", []))}
exp["pod_facts"] = [pod_facts(p) for p in json.load(open(os.path.join(truth, "kubectl-pods.json")))["items"]]
exp["kubectl_pods"] = sorted(f'{p["metadata"]["namespace"]}/{p["metadata"]["name"]}/{p["metadata"]["uid"]}' for p in kp)
a = exp["audit"]
a["lines"] = len(lines)
def decide(e):
    user = e["user"]["username"]; o = e.get("objectRef", {}); res, sub, verb = o.get("resource", ""), o.get("subresource", ""), e["verb"]
    if user == "system:anonymous" or "system:unauthenticated" in e["user"].get("groups", []): return "anonymous"
    if component(user): return ""
    if res == "pods" and sub in ("exec", "attach", "portforward"): return sub
    if res == "secrets" and verb in ("get", "list", "watch"): return "secret_read"
    if res in ("pods", "roles", "rolebindings", "clusterroles", "clusterrolebindings") and sub == "" and verb in ("create", "delete", "deletecollection"): return "change"
    if res in ("roles", "rolebindings", "clusterroles", "clusterrolebindings") and sub == "" and verb in ("update", "patch"): return "change"
    return ""
cats = {}
for raw in lines:
    c = decide(json.loads(raw))
    if c: cats[c] = cats.get(c, 0) + 1
a["categories"] = cats
json.dump(exp, open(os.path.join(dest, "expected.json"), "w"), indent=1, sort_keys=True)
print(dest, "audit lines", len(lines), cats)
