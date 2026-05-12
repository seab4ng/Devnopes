# devnopes

A Kubernetes Job that checks **cluster infrastructure only** and returns a clear verdict — designed for airgap environments.

## What it checks

| Check | What a failure means |
|---|---|
| `/etc/resolv.conf` | kubelet not injecting DNS config into pods |
| Cluster DNS resolution + timing | CoreDNS broken or slow |
| CoreDNS pod health + recent logs | CoreDNS down or returning errors |
| kube-proxy daemonset + recent logs | Service routing rules not being applied |
| CNI plugin pods | Pod-to-pod networking broken on a node |
| Node conditions | NotReady, MemoryPressure, DiskPressure, PIDPressure |
| Core system pods | kube-apiserver, etcd, scheduler, controller-manager |
| API server reachability | Control plane not reachable |

## Install

```bash
helm repo add devnopes https://seab4ng.github.io/Devnopes
helm repo update
helm install devnopes devnopes/devnopes -n kube-system
```

## View results

```bash
kubectl logs -n kube-system job/devnopes --follow
```

The job exits **0** (`Complete`) when healthy, **1** (`Failed`) when issues are found.

## Re-run

```bash
kubectl delete job devnopes -n kube-system
helm upgrade devnopes devnopes/devnopes -n kube-system
```

## Values

| Key | Default | Description |
|---|---|---|
| `image.repository` | `your-dockerhub-username/devnopes` | Image to run |
| `image.tag` | `latest` | Image tag |
| `config.clusterDomain` | `cluster.local` | Cluster DNS domain |
| `config.dnsSlowThreshold` | `0.5` | DNS slow flag threshold (seconds) |
| `config.logScanSeconds` | `300` | How far back to scan logs (seconds) |
| `networkPathTest.enabled` | `false` | Enable 4-step service network path test |
| `networkPathTest.service` | `""` | Service name to test |
| `networkPathTest.namespace` | `default` | Namespace of the service |
| `networkPathTest.port` | `80` | Port to TCP-probe |
| `cniConfMount.enabled` | `true` | Mount `/etc/cni/net.d` for CNI detection |
| `job.ttlSecondsAfterFinished` | `3600` | Auto-delete job after completion |

## Airgap usage

Mirror the image to your internal registry and set `image.repository`:

```bash
helm install devnopes devnopes/devnopes \
  -n kube-system \
  --set image.repository=registry.internal.corp/tools/devnopes
```
