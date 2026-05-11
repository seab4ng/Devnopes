# devnopes

A Kubernetes Job that checks **cluster infrastructure only** and returns a clear verdict:

```
██  IT TEAM / INFRASTRUCTURE RESPONSIBILITY  ██
██  INFRASTRUCTURE IS HEALTHY               ██
```

Designed for **airgap environments**. The running container needs zero internet access — all dependencies are baked into the image at build time.

---

## What it checks

| Check | What a failure means |
|---|---|
| `/etc/resolv.conf` | kubelet is not injecting DNS config into pods |
| Cluster DNS resolution + timing | CoreDNS broken or slow |
| CoreDNS pod health + recent logs | CoreDNS down or returning errors right now |
| kube-proxy daemonset + recent logs | Service routing rules not being applied |
| CNI plugin pods | Pod-to-pod networking broken on a node |
| Node conditions | NotReady, NetworkUnavailable, MemoryPressure, DiskPressure, PIDPressure |
| Core system pods | kube-apiserver, etcd, scheduler, controller-manager not healthy |
| API server reachability | Control plane not reachable via DNS or TCP |
| Service network path test *(optional)* | Pinpoints exactly where in DNS → ClusterIP → Pod IP the failure is |

**Log scanning policy:** logs are read only for CoreDNS and kube-proxy, only for patterns that are unambiguously a failure of that component's function (`[ERROR]`, `SERVFAIL`, `Failed to sync iptables rules`, etc.), and only for the last `LOG_SCAN_SECONDS` seconds. A pod that is Running/Ready but logging these errors IS a current infrastructure problem.

**What is never flagged:** historical restart counts, old log lines, unrelated warnings, or anything from application workloads.

---

## Airgap usage

The image is built in CI (which has internet) and pushed to Docker Hub. In airgap, you mirror it to your internal registry — the running container needs no outbound connectivity.

### Step 1 — Mirror the image to your internal registry

```bash
# On a machine with internet access:
docker pull your-dockerhub-username/devnopes:latest
docker tag  your-dockerhub-username/devnopes:latest \
            registry.internal.corp/tools/devnopes:latest
docker push registry.internal.corp/tools/devnopes:latest
```

### Step 2 — Update the image reference

**Helm** — set in `values.yaml` or with `--set`:
```bash
helm install devnopes ./helm \
  --set image.repository=registry.internal.corp/tools/devnopes
```

**kubectl** — edit the `image:` field in `k8s/job.yaml` before applying.

---

## Quick start (kubectl)

```bash
# 1. Apply RBAC (once per cluster)
kubectl apply -f k8s/rbac.yaml

# 2. Run the job
kubectl apply -f k8s/job.yaml

# 3. Watch the verdict
kubectl logs -n kube-system -l job-name=devnopes -f

# 4. Re-run (delete the completed job and apply again)
kubectl delete job devnopes -n kube-system
kubectl apply  -f k8s/job.yaml
```

To enable the service network path test, uncomment `TARGET_SERVICE` in `k8s/job.yaml`.

---

## Helm chart

```bash
# Install (basic — infrastructure checks only)
helm install devnopes ./helm \
  -n kube-system \
  --set image.repository=registry.internal.corp/tools/devnopes

# Install with service network path test enabled
helm install devnopes ./helm \
  -n kube-system \
  --set image.repository=registry.internal.corp/tools/devnopes \
  --set networkPathTest.enabled=true \
  --set networkPathTest.service=my-app \
  --set networkPathTest.namespace=production \
  --set networkPathTest.port=8080

# Re-run (delete Job and upgrade to recreate it)
kubectl delete job devnopes -n kube-system
helm upgrade devnopes ./helm -n kube-system

# Uninstall
helm uninstall devnopes -n kube-system
```

---

## Environment variables

All variables are optional — defaults work for standard clusters.

| Variable | Default | Description |
|---|---|---|
| `CLUSTER_DOMAIN` | `cluster.local` | Cluster DNS domain |
| `DNS_SLOW_THRESHOLD` | `0.5` | Seconds above which DNS resolution is flagged as slow |
| `DNS_TIMEOUT` | `3.0` | Hard timeout per DNS query (seconds) |
| `CONNECT_TIMEOUT` | `3.0` | Hard timeout for TCP connect probes (seconds) |
| `LOG_SCAN_SECONDS` | `300` | How far back to look in CoreDNS/kube-proxy logs (seconds) |
| `TARGET_SERVICE` | *(unset)* | **Optional.** Service name to run the 4-step network path test on |
| `TARGET_NAMESPACE` | `default` | Namespace of `TARGET_SERVICE` |
| `TARGET_PORT` | `80` | Port to TCP-probe for the network path test |

### The service network path test (4 steps)

When `TARGET_SERVICE` is set, the tool runs:

1. **DNS** — resolve `<service>.<namespace>.svc.<domain>` and measure time
2. **ClusterIP from API** — get the real ClusterIP from K8s (ground truth)
3. **ClusterIP TCP** — TCP connect to `ClusterIP:port` → tests kube-proxy / iptables
4. **Pod IP TCP** — TCP connect directly to a pod IP → tests CNI

The combination of results pinpoints the failure layer:

| DNS | ClusterIP TCP | Pod IP TCP | Conclusion |
|---|---|---|---|
| ✗ | ✗ | ✗ | CNI broken — pod networking down |
| ✗ | ✗ | ✓ | CoreDNS + kube-proxy both broken |
| ✗ | ✓ | ✓ | **CoreDNS broken** (pod/service networking works) |
| ✓ | ✗ | ✓ | **kube-proxy / iptables broken** |
| ✓ | ✓ | ✓ | Infrastructure healthy |

---

## CI — GitHub Actions

The pipeline (`.github/workflows/ci.yml`) does:

1. Installs `uv` (fast Python package manager — written in Rust)
2. Runs `uv lock` — generates/verifies `uv.lock` (the dependency lockfile)
3. Runs `uv sync --frozen --no-dev` — installs deps in CI for verification
4. Builds the Docker image (multi-stage; all packages baked in at build time)
5. Pushes to Docker Hub **only on version tag** (`v*`) — plain pushes to `main` are build-check only

### Required GitHub secrets

Go to **Settings → Secrets and variables → Actions → New repository secret**:

| Secret name | Where to get it |
|---|---|
| `DOCKERHUB_USERNAME` | Your Docker Hub username |
| `DOCKERHUB_TOKEN` | Docker Hub → Account Settings → Security → New Access Token |

The image is pushed to `<DOCKERHUB_USERNAME>/devnopes`.

### Image tags produced

| Event | Build | Push |
|---|---|---|
| Push to `main` | ✓ (build check only) | ✗ |
| Push of `v1.2.3` tag | ✓ | ✓ — tags `1.2.3`, `1.2`, `1`, `latest` |

### To release a new version

```bash
git tag v1.0.0
git push origin v1.0.0
```

---

## Building the image locally

Requires internet access (downloads base image and packages). The resulting image is fully self-contained and airgap-safe.

```bash
# Generate the lockfile first if you haven't already (see Dependency management below)
uv lock

# Build
docker build -t devnopes:local .

# Run locally against your current kubeconfig context
docker run --rm \
  -v ~/.kube/config:/root/.kube/config:ro \
  -e CLUSTER_DOMAIN=cluster.local \
  devnopes:local
```

---

## Dependency management (uv)

[uv](https://docs.astral.sh/uv/) is a modern Python package manager written in Rust. It replaces `pip` + `pip-tools` and generates `uv.lock` — a lockfile that pins every dependency to an exact version and hash, guaranteeing identical builds everywhere.

### First-time setup (needs internet, done once by a developer)

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Generate uv.lock from pyproject.toml and commit it
uv lock
git add uv.lock
git commit -m "Add uv lockfile"
```

### Local development

```bash
uv sync --no-dev           # install exact locked versions
uv run python diagnose.py  # run with the managed venv
```

### Updating dependencies

```bash
uv lock --upgrade          # resolve latest allowed versions
git add uv.lock && git commit -m "Update lockfile"
```

---

## CNI detection layers

The tool identifies the installed CNI using three layers, falling back in order:

1. **`/etc/cni/net.d/`** (hostPath volume) — reads the CNI JSON config file that kubelet itself uses. Most reliable. Enabled by default.
2. **CRDs** — matches installed CRD API groups against known signatures (`projectcalico.org`, `cilium.io`, `antrea.io`, …). No hostPath needed.
3. **Pod label scan** (fallback) — scans kube-system pods with known label selectors. Least reliable; can miss custom installs.

Disable the hostPath mount (`cniConfMount.enabled: false` in Helm / comment out the volume in `k8s/job.yaml`) if your security policy prohibits it — layers 2 and 3 activate automatically.
