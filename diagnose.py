#!/usr/bin/env python3
"""
devnopes: Cluster Infrastructure Health Checker
Checks ONLY cluster-level components — not application workloads.

Verdict:
  IT TEAM RESPONSIBILITY  — if any infrastructure issue is found
  INFRASTRUCTURE HEALTHY  — if all checks pass

Checks performed (all infrastructure / cluster-owned):
  1.  Pod DNS resolver config  (/etc/resolv.conf)
  2.  Cluster DNS resolution + timing  (CoreDNS)
  3.  CoreDNS pod health + recent log errors
  4.  kube-proxy daemonset health + recent log errors
  5.  CNI plugin pod health  (Calico / Flannel / Cilium / Weave / Antrea / Canal)
  6.  Node conditions  (Ready, NetworkUnavailable, MemoryPressure, DiskPressure, PIDPressure)
  7.  Core system pods health  (kube-system: apiserver, scheduler, etcd, controller-manager)
  8.  Kubernetes API server reachability
  9.  [optional] Service network path test: DNS → ClusterIP TCP → Pod IP TCP
      (set TARGET_SERVICE env var to enable — tests the network path, not the app)

Log scanning policy:
  Logs are scanned ONLY for CoreDNS and kube-proxy, and ONLY for patterns that
  are unambiguously a failure of that component's specific function.
  We look at the last LOG_SCAN_SECONDS seconds only (default: 300 = 5 minutes).
  A pod that is Running/Ready but logging these errors IS a current infra problem.
  Generic "error" words, unrelated warnings, or old log lines are never flagged.
"""

import os
import re
import sys
import time
import socket
import threading
from datetime import datetime, timezone

# ─── Configuration ────────────────────────────────────────────────────────────
CLUSTER_DOMAIN      = os.environ.get("CLUSTER_DOMAIN",      "cluster.local")
DNS_SLOW_THRESHOLD  = float(os.environ.get("DNS_SLOW_THRESHOLD", "0.5"))
DNS_TIMEOUT         = float(os.environ.get("DNS_TIMEOUT",    "3.0"))
CONNECT_TIMEOUT     = float(os.environ.get("CONNECT_TIMEOUT","3.0"))
# How far back to look in pod logs. Only the last N seconds are scanned.
# Older entries are ignored — they are historical and not the current problem.
LOG_SCAN_SECONDS    = int(os.environ.get("LOG_SCAN_SECONDS", "300"))   # default: 5 minutes

# Optional: test a specific service's network path (infrastructure path only, not the app)
TARGET_SERVICE      = os.environ.get("TARGET_SERVICE",  "")
TARGET_NAMESPACE    = os.environ.get("TARGET_NAMESPACE","default")
TARGET_PORT         = int(os.environ.get("TARGET_PORT", "80"))

# ─── Per-component namespace / label overrides ────────────────────────────────
# Every check has built-in default lists. Env vars only ADD to those lists —
# omitting them leaves all defaults intact.

def _split_env(key):
    """Return non-empty stripped items from a comma-separated env var."""
    return [s.strip() for s in os.environ.get(key, "").split(",") if s.strip()]

# CoreDNS — searched in order; first match wins
_COREDNS_NAMESPACES = ["kube-system"] + _split_env("COREDNS_EXTRA_NAMESPACES")
_COREDNS_LABEL_SELECTORS = [
    "k8s-app=kube-dns",
    "app=coredns",
    "app.kubernetes.io/name=coredns",
    "k8s-app=coredns",
] + _split_env("COREDNS_EXTRA_LABELS")

# kube-proxy — searched in order; first match wins
_KUBE_PROXY_NAMESPACES = ["kube-system"] + _split_env("KUBE_PROXY_EXTRA_NAMESPACES")
_KUBE_PROXY_POD_SELECTORS = [
    "k8s-app=kube-proxy",
    "component=kube-proxy",
    "app=kube-proxy",
] + _split_env("KUBE_PROXY_EXTRA_LABELS")

# ─── Finding bucket — only one category: IT Team ─────────────────────────────
IT_ISSUES = []    # every problem here is cluster/infra — IT Team's responsibility
WARNINGS  = []    # informational / unable to verify

# ─── Output helpers ───────────────────────────────────────────────────────────
def ts():
    return datetime.now().strftime("%H:%M:%S")

def log(msg, level="INFO"):
    icon = {"OK": "✓", "FAIL": "✗", "WARN": "⚠", "INFO": "·"}.get(level, "·")
    print(f"[{ts()}] {icon} {msg}", flush=True)

def section(title):
    print(f"\n{'─'*64}", flush=True)
    print(f"  {title}", flush=True)
    print(f"{'─'*64}", flush=True)


# ─── Network primitives ───────────────────────────────────────────────────────
def resolve_with_timing(hostname, timeout=None):
    """Returns (ip_list, elapsed, error_string). Hard-timeouts via daemon thread."""
    timeout = timeout or DNS_TIMEOUT
    ips, err = [None], [None]

    def _work():
        try:
            results = socket.getaddrinfo(hostname, None, socket.AF_INET)
            ips[0] = list(dict.fromkeys(r[4][0] for r in results))
        except Exception as e:
            err[0] = str(e)

    start = time.monotonic()
    t = threading.Thread(target=_work, daemon=True)
    t.start()
    t.join(timeout=timeout)
    elapsed = time.monotonic() - start

    if t.is_alive():
        return None, elapsed, f"timed out after {elapsed:.1f}s"
    return ips[0], elapsed, err[0]


def tcp_connect(host, port, timeout=None):
    """Returns (success, elapsed, error_string)."""
    timeout = timeout or CONNECT_TIMEOUT
    start = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True, time.monotonic() - start, None
    except Exception as e:
        return False, time.monotonic() - start, str(e)


def _resolve_with_retry(hostname, timeout=None):
    """Resolve once; if failed or slow, wait 1s and try once more. Returns final result."""
    ips, elapsed, err = resolve_with_timing(hostname, timeout)
    if err or elapsed > DNS_SLOW_THRESHOLD:
        time.sleep(1.0)
        return resolve_with_timing(hostname, timeout)
    return ips, elapsed, err


def _tcp_with_retry(host, port, timeout=None):
    """Connect once; if failed, wait 1s and try once more. Returns final result."""
    ok, elapsed, err = tcp_connect(host, port, timeout)
    if not ok:
        time.sleep(1.0)
        return tcp_connect(host, port, timeout)
    return ok, elapsed, err


# ─── K8s client ───────────────────────────────────────────────────────────────
def init_k8s():
    try:
        from kubernetes import client, config
        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()
        return client
    except Exception as e:
        log(f"Kubernetes client unavailable: {e}", "WARN")
        WARNINGS.append("K8s API client could not be initialised — API-based checks skipped")
        return None


# ─── Log scanning helper ──────────────────────────────────────────────────────
#
# We only ever call this for two infrastructure components:
#   - CoreDNS  (DNS function)
#   - kube-proxy  (service routing function)
#
# Each call receives a hand-crafted list of patterns that are specific to that
# component's function. A generic "error" string is never a pattern.
# We only look at the last LOG_SCAN_SECONDS seconds to avoid historical noise.

def _scan_logs_for_patterns(k8s, namespace, pod_name, container, patterns):
    """
    Fetch the last LOG_SCAN_SECONDS seconds of logs for one container and
    search for specific patterns.

    patterns: list of (compiled_regex, human_readable_meaning)

    Returns list of (meaning, example_line) for each pattern that matched.
    At most one example line is returned per pattern to keep output concise.
    """
    v1 = k8s.CoreV1Api()
    try:
        raw = v1.read_namespaced_pod_log(
            pod_name, namespace,
            container=container,
            since_seconds=LOG_SCAN_SECONDS,
            timestamps=False,
            limit_bytes=256 * 1024,   # 256 KB cap — never read full multi-GB logs
        )
    except Exception as e:
        WARNINGS.append(f"Could not read logs for {pod_name}/{container}: {e}")
        return []

    hits = []
    seen_patterns = set()
    for line in raw.splitlines():
        for pattern, meaning in patterns:
            if meaning in seen_patterns:
                continue
            if pattern.search(line):
                hits.append((meaning, line.strip()))
                seen_patterns.add(meaning)
    return hits


# ─── Check 1: /etc/resolv.conf ────────────────────────────────────────────────
def check_resolv_conf():
    section("POD DNS RESOLVER CONFIG  (/etc/resolv.conf)")
    try:
        with open("/etc/resolv.conf") as f:
            lines = f.read().strip().splitlines()

        nameservers = [l.split()[1] for l in lines if l.startswith("nameserver")]
        search      = next((l.split()[1:] for l in lines if l.startswith("search")), [])
        options     = next((l for l in lines if l.startswith("options")), None)

        for ns in nameservers:
            log(f"nameserver : {ns}", "INFO")
        log(f"search     : {' '.join(search) or '(none)'}", "INFO")
        if options:
            log(f"options    : {options}", "INFO")

        if not nameservers:
            log("No nameserver entries found", "FAIL")
            IT_ISSUES.append(
                "No nameserver in /etc/resolv.conf — "
                "cluster DNS is not injected into pods (kubelet or CNI misconfiguration)"
            )

    except Exception as e:
        log(f"Cannot read /etc/resolv.conf: {e}", "WARN")
        WARNINGS.append(f"Could not read /etc/resolv.conf: {e}")


# ─── Check 2: Cluster DNS resolution + timing ─────────────────────────────────
def check_cluster_dns(k8s=None):
    section("CLUSTER DNS RESOLUTION  (CoreDNS)")

    # These FQDNs MUST resolve in any healthy cluster — they are cluster-owned, not app-owned.
    # Short-name resolution (e.g. bare "kubernetes") is intentionally excluded: from kube-system
    # it must traverse every search domain including host-injected suffixes (Azure/AWS/GCP
    # internal domains), causing multi-second timeouts that are unrelated to CoreDNS health.
    probes = [
        (f"kubernetes.default.svc.{CLUSTER_DOMAIN}",  "K8s API service (canonical cluster DNS test)"),
    ]

    # Discover the CoreDNS service name dynamically — distros vary:
    # standard="kube-dns", RKE2="rke2-coredns-rke2-coredns", etc.
    coredns_svc_name = None
    coredns_svc_ns   = None
    if k8s:
        v1 = k8s.CoreV1Api()
        for ns in _COREDNS_NAMESPACES:
            for selector in _COREDNS_LABEL_SELECTORS:
                try:
                    svcs = v1.list_namespaced_service(ns, label_selector=selector).items
                    if svcs:
                        coredns_svc_name = svcs[0].metadata.name
                        coredns_svc_ns   = ns
                        break
                except Exception:
                    pass
            if coredns_svc_name:
                break

    if coredns_svc_name:
        probes.append(
            (f"{coredns_svc_name}.{coredns_svc_ns}.svc.{CLUSTER_DOMAIN}", f"CoreDNS service ({coredns_svc_name})")
        )
    else:
        probes.append(
            (f"kube-dns.kube-system.svc.{CLUSTER_DOMAIN}", "CoreDNS service (kube-dns fallback)")
        )

    for name, description in probes:
        ips, elapsed, err = _resolve_with_retry(name)
        if err:
            log(f"FAIL  {name}", "FAIL")
            log(f"      ({description})", "INFO")
            log(f"      error: {err}", "INFO")
            IT_ISSUES.append(
                f"DNS resolution failed — '{name}' ({description}): {err}"
            )
        elif elapsed > DNS_SLOW_THRESHOLD:
            log(f"SLOW  {name}  →  {ips}  ({elapsed:.3f}s  >  {DNS_SLOW_THRESHOLD}s)", "WARN")
            log(f"      ({description})", "INFO")
            IT_ISSUES.append(
                f"DNS slow — '{name}' resolved in {elapsed:.3f}s "
                f"(threshold {DNS_SLOW_THRESHOLD}s): "
                f"CoreDNS overloaded, upstream forwarder unreachable, or ndots misconfigured"
            )
        else:
            log(f"OK    {name}  →  {ips}  ({elapsed:.3f}s)", "OK")

    # NXDOMAIN sanity — proves CoreDNS is actually answering authoritatively
    nxname = f"nxdomain-probe-xyzabc99.kube-system.svc.{CLUSTER_DOMAIN}"
    ips, elapsed, err = resolve_with_timing(nxname, timeout=DNS_TIMEOUT)
    if ips:
        log(f"WARN  NXDOMAIN probe resolved to {ips} — wildcard DNS active?", "WARN")
        WARNINGS.append(
            "Wildcard DNS detected: non-existent cluster names resolve to an IP. "
            "DNS failures may be silently masked."
        )
    elif err and elapsed < DNS_TIMEOUT:
        log(f"OK    NXDOMAIN probe: non-existent name correctly refused  ({elapsed:.3f}s)", "OK")
    else:
        log(f"WARN  NXDOMAIN probe timed out ({elapsed:.3f}s) — CoreDNS may be unresponsive", "WARN")
        IT_ISSUES.append(
            f"CoreDNS did not respond to NXDOMAIN probe within {DNS_TIMEOUT}s — "
            "DNS queries may be silently dropped"
        )


# ─── Check 3: CoreDNS pod health + log scan ───────────────────────────────────
#
# Log patterns matched here are reported as WARNINGS (not IT_ISSUES) because
# CoreDNS logs [ERROR]/SERVFAIL/i/o timeout for upstream forwarding failures
# (e.g. external nameservers unreachable in restricted/CI networks). These are
# NOT cluster-internal DNS failures. The authoritative DNS health test is
# check_cluster_dns() above which directly probes cluster FQDNs.

_COREDNS_LOG_PATTERNS = [
    (re.compile(r'\[ERROR\]',          re.IGNORECASE), "CoreDNS [ERROR] in recent logs"),
    (re.compile(r'SERVFAIL',           re.IGNORECASE), "CoreDNS returning SERVFAIL to clients"),
    (re.compile(r'i/o timeout',        re.IGNORECASE), "CoreDNS upstream i/o timeout"),
    (re.compile(r'no route to host',   re.IGNORECASE), "CoreDNS: no route to upstream host"),
    (re.compile(r'connection refused', re.IGNORECASE), "CoreDNS upstream connection refused"),
]

def check_coredns(k8s):
    section("COREDNS PODS")
    v1 = k8s.CoreV1Api()

    pods = []
    found_ns = None
    for ns in _COREDNS_NAMESPACES:
        for selector in _COREDNS_LABEL_SELECTORS:
            try:
                pods = v1.list_namespaced_pod(ns, label_selector=selector).items
                if pods:
                    found_ns = ns
                    break
            except Exception as e:
                WARNINGS.append(f"Could not list CoreDNS pods in {ns}: {e}")
        if pods:
            break

    if not pods:
        searched = ", ".join(_COREDNS_NAMESPACES)
        log(f"No CoreDNS/kube-dns pods found (searched: {searched})", "FAIL")
        IT_ISSUES.append(
            f"CRITICAL: No CoreDNS/kube-dns pods found in [{searched}] — "
            "cluster DNS component is missing or deleted"
        )
        return

    log(f"INFO  Found CoreDNS pods in namespace: {found_ns}", "INFO")

    for pod in pods:
        name      = pod.metadata.name
        node      = pod.spec.node_name
        phase     = pod.status.phase
        cs_list   = pod.status.container_statuses or []
        ready     = all(cs.ready for cs in cs_list)
        restarts  = sum(cs.restart_count for cs in cs_list)

        if phase == "Running" and ready:
            log(f"OK    {name}  node={node}  Running/Ready  (restarts={restarts})", "OK")

            # Pod is up — scan recent logs for DNS-function patterns.
            # Matches go to WARNINGS (not IT_ISSUES): upstream forwarding errors
            # are common in restricted networks and do not mean cluster DNS is broken.
            container_name = cs_list[0].name if cs_list else "coredns"
            hits = _scan_logs_for_patterns(k8s, found_ns, name, container_name,
                                           _COREDNS_LOG_PATTERNS)
            if hits:
                for meaning, example in hits:
                    log(f"WARN  {name}  log pattern: {meaning}", "WARN")
                    log(f"      example: {example[:120]}", "INFO")
                    WARNINGS.append(
                        f"CoreDNS pod '{name}' has recent log patterns "
                        f"({meaning}) — may indicate upstream DNS forwarding issues "
                        f"(not a cluster-internal DNS failure if FQDN resolution above passed). "
                        f"Example: {example[:120]}"
                    )
            else:
                log(f"OK    {name}  no relevant errors in last {LOG_SCAN_SECONDS}s of logs", "OK")
        else:
            # Pod is not healthy right now
            reason = phase
            for cs in cs_list:
                if cs.state and cs.state.waiting and cs.state.waiting.reason:
                    reason = cs.state.waiting.reason
                    break
                if cs.state and cs.state.terminated and cs.state.terminated.reason:
                    reason = cs.state.terminated.reason
                    break
            log(f"FAIL  {name}  node={node}  {reason}  (restarts={restarts})", "FAIL")
            IT_ISSUES.append(
                f"CoreDNS pod '{name}' is currently {reason} — cluster DNS is degraded right now"
            )


# ─── Check 4: kube-proxy ──────────────────────────────────────────────────────
#
# Log patterns: ONLY errors that mean kube-proxy is failing to program
# service routing rules right now. Nothing else.
# - Failed to sync iptables/ipvs rules  → ClusterIP routing is broken
# - error syncing rules                 → same, different log format
#
# What we do NOT flag: informational messages, reflected config changes,
# conntrack entries, node port events, or any generic warnings.

_KUBE_PROXY_LOG_PATTERNS = [
    (re.compile(r'Failed to sync iptables rules', re.IGNORECASE), "kube-proxy failed to sync iptables rules"),
    (re.compile(r'Failed to sync ipvs rules',     re.IGNORECASE), "kube-proxy failed to sync ipvs rules"),
    (re.compile(r'error syncing rules',           re.IGNORECASE), "kube-proxy error syncing rules"),
]

def _check_kube_proxy_pods(k8s, pods, source):
    """Check readiness and scan logs for a list of kube-proxy pods."""
    v1 = k8s.CoreV1Api()
    total = len(pods)
    unhealthy = []
    for pod in pods:
        phase   = pod.status.phase
        cs_list = pod.status.container_statuses or []
        ready   = all(cs.ready for cs in cs_list) if cs_list else (phase == "Running")
        if not ready:
            unhealthy.append(pod.metadata.name)

    if unhealthy:
        log(f"FAIL  kube-proxy: {total - len(unhealthy)}/{total} pods ready  ({source})", "FAIL")
        IT_ISSUES.append(
            f"kube-proxy: {total - len(unhealthy)}/{total} pods ready — "
            "ClusterIP and NodePort routing is broken on unreachable nodes"
        )
    else:
        log(f"OK    kube-proxy: {total}/{total} pods ready  ({source})", "OK")

        for pod in pods[:2]:
            cs_list = pod.status.container_statuses or []
            container_name = cs_list[0].name if cs_list else "kube-proxy"
            ns = pod.metadata.namespace or "kube-system"
            hits = _scan_logs_for_patterns(k8s, ns, pod.metadata.name,
                                           container_name, _KUBE_PROXY_LOG_PATTERNS)
            if hits:
                for meaning, example in hits:
                    log(f"FAIL  {pod.metadata.name}  log error: {meaning}", "FAIL")
                    log(f"      example: {example[:120]}", "INFO")
                    IT_ISSUES.append(
                        f"kube-proxy pod '{pod.metadata.name}' is Running/Ready but "
                        f"has recent log errors ({meaning}) — "
                        f"service routing rules are not being applied correctly. "
                        f"Example: {example[:120]}"
                    )
            else:
                log(f"OK    {pod.metadata.name}  no rule-sync errors in last {LOG_SCAN_SECONDS}s of logs", "OK")


def check_kube_proxy(k8s):
    section("KUBE-PROXY  (service routing)")
    apps_api = k8s.AppsV1Api()
    v1       = k8s.CoreV1Api()

    # Search for kube-proxy DaemonSet by label selector across all configured namespaces.
    # DaemonSet metadata labels match pod selector labels in standard installs.
    ds = None
    ds_ns = None
    for selector in _KUBE_PROXY_POD_SELECTORS:
        for ns in _KUBE_PROXY_NAMESPACES:
            try:
                dsets = apps_api.list_namespaced_daemon_set(ns, label_selector=selector).items
                if dsets:
                    ds    = dsets[0]
                    ds_ns = ns
                    break
            except Exception:
                pass
        if ds:
            break

    if ds is not None:
        ds_name = ds.metadata.name
        desired = ds.status.desired_number_scheduled or 0
        ready   = ds.status.number_ready or 0
        updated = ds.status.updated_number_scheduled or 0

        if ready < desired:
            log(f"FAIL  kube-proxy ({ds_name}/{ds_ns}): {ready}/{desired} pods ready  (updated={updated})", "FAIL")
            IT_ISSUES.append(
                f"kube-proxy: {ready}/{desired} pods ready — "
                "ClusterIP and NodePort routing is broken on unreachable nodes"
            )
        else:
            log(f"OK    kube-proxy ({ds_name}/{ds_ns}): {ready}/{desired} pods ready", "OK")
            pods = []
            for selector in _KUBE_PROXY_POD_SELECTORS:
                try:
                    pods = v1.list_namespaced_pod(ds_ns, label_selector=selector).items
                    if pods:
                        break
                except Exception:
                    pass
            _check_kube_proxy_pods(k8s, pods[:2], f"daemonset/{ds_name}")
        return

    # DaemonSet not found — some distros (RKE2) run kube-proxy pods without a DaemonSet.
    # Fall back to pod label scan across all configured namespaces.
    log("INFO  kube-proxy DaemonSet not found by label — checking for pods by label", "INFO")
    pods = []
    found_ns = None
    for selector in _KUBE_PROXY_POD_SELECTORS:
        for ns in _KUBE_PROXY_NAMESPACES:
            try:
                found = v1.list_namespaced_pod(ns, label_selector=selector).items
                if found:
                    pods     = found
                    found_ns = ns
                    break
            except Exception as e:
                WARNINGS.append(f"Could not list kube-proxy pods ({selector}) in {ns}: {e}")
        if pods:
            break

    if pods:
        _check_kube_proxy_pods(k8s, pods, f"pod label scan/{found_ns}")
    else:
        searched_ns = ", ".join(_KUBE_PROXY_NAMESPACES)
        log("INFO  kube-proxy not found (no DaemonSet, no pods) — eBPF dataplane assumed (Cilium / Calico eBPF)", "INFO")
        WARNINGS.append(
            f"kube-proxy not found (no DaemonSet or pods matching {_KUBE_PROXY_POD_SELECTORS} "
            f"in [{searched_ns}]); "
            "cluster likely uses an eBPF dataplane. Verify CNI handles service routing."
        )


# ─── Check 5: CNI plugin ──────────────────────────────────────────────────────
#
# CNI detection uses three layers, each more reliable than the next fallback:
#
#   Layer 1 — /etc/cni/net.d/ (host path, mounted as volume)
#             The standard CNI config directory written by any CNI installer.
#             Config files contain an explicit "type" or "name" field.
#             This is authoritative — it's what kubelet actually reads.
#
#   Layer 2 — CRDs (Kubernetes API)
#             Calico, Cilium, and Antrea register cluster-scoped CRDs with
#             distinctive group names. Flannel and Weave do not, so this
#             layer cannot identify them.
#
#   Layer 3 — Pod label scan across known CNI namespaces (last resort)
#             Heuristic only. Covers all known CNI installers and namespaces.
#             Extend via CNI_EXTRA_LABELS / CNI_EXTRA_NAMESPACES env vars.
#
# The hostPath mount (/host/etc/cni/net.d) must be configured in job.yaml.
# If the mount is missing the directory simply won't exist and we skip to Layer 2.

CNI_CONF_DIR = "/host/etc/cni/net.d"   # mounted from host in job.yaml

# CRD group substrings that uniquely identify a CNI
_CNI_CRD_SIGNATURES = [
    ("projectcalico.org",   "Calico"),
    ("crd.projectcalico.org", "Calico"),
    ("cilium.io",           "Cilium"),
    ("antrea.io",           "Antrea"),
    ("k8s.ovn.org",         "OVN-Kubernetes"),
    ("submariner.io",       "Submariner"),
    ("nsx.vmware.com",      "NSX-T"),
    ("k8s.cni.cncf.io",    "Multus"),
]

# Pod label selectors per CNI — only used in Layer 3.
# Multiple selectors per CNI cover different installer versions and distros.
_CNI_POD_LABELS = [
    # Calico (Tigera Operator and standalone installs)
    ("k8s-app=calico-node",                     "Calico"),
    ("app.kubernetes.io/name=calico",            "Calico"),
    ("app.kubernetes.io/component=calico-node",  "Calico"),
    # Flannel (upstream manifest, kube-flannel namespace installs, RKE/RKE2)
    ("app=flannel",                              "Flannel"),
    ("k8s-app=flannel",                          "Flannel"),
    ("app.kubernetes.io/name=flannel",           "Flannel"),
    ("k8s-app=kube-flannel",                     "Flannel"),
    # Cilium (standalone, Helm, and managed variants)
    ("app=cilium",                               "Cilium"),
    ("k8s-app=cilium",                           "Cilium"),
    ("app.kubernetes.io/name=cilium-agent",      "Cilium"),
    ("app.kubernetes.io/part-of=cilium",         "Cilium"),
    # Weave Net
    ("name=weave-net",                           "Weave"),
    ("k8s-app=weave-net",                        "Weave"),
    # Canal (Flannel + Calico policy — common in RKE1)
    ("app=canal",                                "Canal"),
    ("k8s-app=canal",                            "Canal"),
    # Antrea
    ("app=antrea-agent",                         "Antrea"),
    ("component=antrea-agent",                   "Antrea"),
    ("app.kubernetes.io/component=antrea-agent", "Antrea"),
    # OVN-Kubernetes (upstream and OpenShift variants)
    ("app=ovs-cni-amd64",                        "OVS-CNI"),
    ("app=ovn-kubernetes-node",                  "OVN-Kubernetes"),
    ("app=ovnkube-node",                         "OVN-Kubernetes"),
    ("component=ovnkube-node",                   "OVN-Kubernetes"),
    # kube-router
    ("app=kube-router",                          "kube-router"),
    ("k8s-app=kube-router",                      "kube-router"),
    # kindnet (kind clusters)
    ("app=kindnet",                              "kindnet"),
    # Multus (meta-CNI — usually paired with another CNI)
    ("app=multus",                               "Multus"),
    ("app.kubernetes.io/name=multus",            "Multus"),
    # NSX-T (VMware)
    ("component=nsx-node-agent",                 "NSX-T"),
    ("app=nsx-node-agent",                       "NSX-T"),
]

# Extra labels from env var CNI_EXTRA_LABELS (comma-separated "selector:FriendlyName").
# Example: CNI_EXTRA_LABELS="app=my-cni:MyCNI,k8s-app=custom-cni:CustomCNI"
_extra_labels_env = os.environ.get("CNI_EXTRA_LABELS", "")
for _item in _extra_labels_env.split(","):
    _item = _item.strip()
    if ":" in _item:
        _sel, _name = _item.rsplit(":", 1)
        _sel, _name = _sel.strip(), _name.strip()
        if _sel and _name:
            _CNI_POD_LABELS.append((_sel, _name))


def _detect_cni_from_conf_dir():
    """
    Layer 1: read /host/etc/cni/net.d/*.conf and *.conflist.
    Returns (cni_name, source_file) or (None, None).
    """
    import json, glob, os

    if not os.path.isdir(CNI_CONF_DIR):
        return None, None

    conf_files = sorted(
        glob.glob(f"{CNI_CONF_DIR}/*.conf") +
        glob.glob(f"{CNI_CONF_DIR}/*.conflist")
    )

    if not conf_files:
        return None, None

    # CNI type strings found in config files → friendly name
    _type_map = {
        "calico":         "Calico",
        "flannel":        "Flannel",
        "cilium-cni":     "Cilium",
        "cilium":         "Cilium",
        "antrea":         "Antrea",
        "weave-net":      "Weave",
        "canal":          "Canal",
        "ovn-k8s-cni-overlay": "OVN-Kubernetes",
        "kube-router":    "kube-router",
        "macvlan":        "macvlan",
        "ipvlan":         "ipvlan",
        "bridge":         "bridge",
        "multus":         "Multus",
    }

    for path in conf_files:
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            continue

        # .conflist wraps plugins in a list
        plugins = data.get("plugins", [data])
        for plugin in plugins:
            cni_type = plugin.get("type", "").lower()
            if cni_type in _type_map:
                return _type_map[cni_type], os.path.basename(path)
            # fall back to the config "name" field
            cni_name_field = plugin.get("name", "").lower()
            for known_type, friendly in _type_map.items():
                if known_type in cni_name_field:
                    return friendly, os.path.basename(path)

    # Files exist but none matched — return the raw type from the first file
    try:
        with open(conf_files[0]) as f:
            data = json.load(f)
        plugins = data.get("plugins", [data])
        raw_type = plugins[0].get("type") or plugins[0].get("name") or "unknown"
        return raw_type, os.path.basename(conf_files[0])
    except Exception:
        return None, None


def _detect_cni_from_crds(k8s):
    """
    Layer 2: list installed CRDs and match against known CNI API group names.
    Returns cni_name or None.
    """
    try:
        ext = k8s.ApiextensionsV1Api()
        crds = ext.list_custom_resource_definition().items
        groups = {crd.spec.group for crd in crds}
        for group in groups:
            for signature, name in _CNI_CRD_SIGNATURES:
                if signature in group:
                    return name
    except Exception:
        pass
    return None


# Namespaces where CNI agent pods may run.
# Covers every known CNI installer default — kube-system is searched first.
_CNI_POD_NAMESPACES = [
    "kube-system",       # most CNIs: Flannel, Canal, kindnet, kube-router, older Calico/Cilium
    "calico-system",     # Calico via Tigera Operator (Rancher, RKE2)
    "tigera-operator",   # Tigera Operator itself
    "cilium",            # Cilium Helm chart default namespace
    "antrea",            # Antrea Helm chart default namespace
    "canal-system",      # Canal on some distros
    "kube-flannel",      # Flannel upstream manifest (newer versions)
    "weave",             # Weave Net
    "ovn-kubernetes",    # OVN-Kubernetes (upstream and OpenShift)
    "nsx-system",        # NSX-T (VMware)
    "multus",            # Multus meta-CNI
]

# Extra namespaces from env var CNI_EXTRA_NAMESPACES (comma-separated).
# Example: CNI_EXTRA_NAMESPACES="networking,my-cni-ns"
_extra_ns_env = os.environ.get("CNI_EXTRA_NAMESPACES", "")
for _ns in _extra_ns_env.split(","):
    _ns = _ns.strip()
    if _ns and _ns not in _CNI_POD_NAMESPACES:
        _CNI_POD_NAMESPACES.append(_ns)


def _detect_cni_from_pods(k8s):
    """
    Layer 3: scan pods by known label selectors across multiple namespaces.
    Returns (cni_name, pods_list) or (None, []).
    """
    v1 = k8s.CoreV1Api()
    for selector, cni_name in _CNI_POD_LABELS:
        for ns in _CNI_POD_NAMESPACES:
            try:
                pods = v1.list_namespaced_pod(ns, label_selector=selector).items
                if pods:
                    return cni_name, pods
            except Exception:
                continue
    return None, []


def _check_cni_pods(k8s, cni_name, pods):
    """Given a CNI name and its pods, check current readiness only."""
    total = len(pods)
    bad = []
    for p in pods:
        phase   = p.status.phase
        cs_list = p.status.container_statuses or []
        ready   = all(cs.ready for cs in cs_list) if cs_list else (phase == "Running")
        if not ready:
            reason = phase
            for cs in cs_list:
                if cs.state and cs.state.waiting and cs.state.waiting.reason:
                    reason = cs.state.waiting.reason
                    break
                if cs.state and cs.state.terminated and cs.state.terminated.reason:
                    reason = cs.state.terminated.reason
                    break
            bad.append((p.metadata.name, p.spec.node_name, reason))

    if bad:
        for pname, node, reason in bad:
            log(f"FAIL  {cni_name} pod '{pname}'  node={node}  currently {reason}", "FAIL")
            IT_ISSUES.append(
                f"CNI ({cni_name}) pod '{pname}' on node '{node}' is currently {reason} — "
                "pod-to-pod networking is broken on that node right now"
            )
    else:
        log(f"OK    {cni_name}: {total}/{total} pods currently ready", "OK")


def check_cni(k8s):
    section("CNI PLUGIN  (pod networking)")

    # ── Layer 1: host CNI config directory ───────────────────────────────────
    cni_name, conf_file = _detect_cni_from_conf_dir()
    if cni_name:
        log(f"INFO  Detected via /etc/cni/net.d/{conf_file}  →  CNI: {cni_name}", "INFO")
        detection = "config file"
    else:
        if CNI_CONF_DIR and __import__("os").path.isdir(CNI_CONF_DIR):
            log(f"WARN  {CNI_CONF_DIR} exists but no recognisable CNI config found", "WARN")
        else:
            log(f"INFO  {CNI_CONF_DIR} not mounted — skipping config-file detection", "INFO")
            log( "INFO  (add hostPath volume in job.yaml for most reliable detection)", "INFO")

        # ── Layer 2: CRDs ─────────────────────────────────────────────────────
        cni_name = _detect_cni_from_crds(k8s)
        if cni_name:
            log(f"INFO  Detected via installed CRDs  →  CNI: {cni_name}", "INFO")
            detection = "CRD"
        else:
            detection = None

    # ── Layer 3: pod labels (fallback / confirmation) ────────────────────────
    pod_cni_name, cni_pods = _detect_cni_from_pods(k8s)

    if not cni_name and not pod_cni_name:
        log("WARN  CNI could not be identified by config file, CRDs, or pod labels", "WARN")
        WARNINGS.append(
            "CNI plugin identity unknown — "
            "mount /etc/cni/net.d from the host (hostPath volume) for reliable detection. "
            "Known CNIs checked: Calico, Flannel, Cilium, Weave, Canal, Antrea, OVN-Kubernetes, "
            "kube-router, kindnet, Multus, NSX-T"
        )
        return

    # If Layer 1/2 and Layer 3 both found something, cross-check them
    if cni_name and pod_cni_name and cni_name != pod_cni_name:
        log(
            f"WARN  CNI name mismatch: {detection} says '{cni_name}', "
            f"pod labels say '{pod_cni_name}'",
            "WARN"
        )
        WARNINGS.append(
            f"CNI identity conflict: config/CRD='{cni_name}', pods='{pod_cni_name}' — "
            "possible multi-CNI setup (e.g. Multus) or misconfiguration"
        )

    final_name = cni_name or pod_cni_name

    if cni_pods:
        _check_cni_pods(k8s, final_name, cni_pods)
    else:
        log(
            f"INFO  CNI identified as '{final_name}' via {detection or 'config'} "
            f"but no agent pods found in searched namespaces",
            "INFO"
        )
        WARNINGS.append(
            f"CNI '{final_name}' identified but no agent pods found — "
            "CNI may run in an unexpected namespace or as a static binary only"
        )


# ─── Check 6: Node conditions ─────────────────────────────────────────────────
def check_nodes(k8s):
    section("NODE CONDITIONS")
    v1 = k8s.CoreV1Api()

    try:
        nodes = v1.list_node().items
    except Exception as e:
        log(f"WARN  Cannot list nodes: {e}", "WARN")
        WARNINGS.append(f"Could not list nodes — API call failed: {e}")
        return

    if not nodes:
        log("No nodes returned from API", "FAIL")
        IT_ISSUES.append("No nodes found — API server may be degraded")
        return

    for node in nodes:
        name     = node.metadata.name
        cond_map = {c.type: c.status for c in node.status.conditions}
        roles    = [
            k.replace("node-role.kubernetes.io/", "")
            for k in (node.metadata.labels or {})
            if k.startswith("node-role.kubernetes.io/")
        ]
        role_str = ",".join(roles) if roles else "worker"

        problems = []
        if cond_map.get("Ready") != "True":
            problems.append("NotReady")
        if cond_map.get("NetworkUnavailable") == "True":
            problems.append("NetworkUnavailable")
        if cond_map.get("MemoryPressure") == "True":
            problems.append("MemoryPressure")
        if cond_map.get("DiskPressure") == "True":
            problems.append("DiskPressure")
        if cond_map.get("PIDPressure") == "True":
            problems.append("PIDPressure")

        if problems:
            log(f"FAIL  {name}  [{role_str}]  conditions: {', '.join(problems)}", "FAIL")
            for p in problems:
                IT_ISSUES.append(
                    f"Node '{name}' [{role_str}]: {p}"
                )
        else:
            log(f"OK    {name}  [{role_str}]  Ready", "OK")


# ─── Check 7: Core system component pods (kube-system) ───────────────────────
def check_system_pods(k8s):
    section("CORE SYSTEM PODS  (kube-system)")
    v1 = k8s.CoreV1Api()

    # Component pod prefixes that belong to the cluster infrastructure
    infra_prefixes = (
        "kube-apiserver",
        "kube-scheduler",
        "kube-controller-manager",
        "etcd",
        "kube-proxy",
        "coredns",
        "kube-dns",
    )

    try:
        all_pods = v1.list_namespaced_pod("kube-system").items
    except Exception as e:
        log(f"WARN  Cannot list kube-system pods: {e}", "WARN")
        WARNINGS.append(f"Could not list kube-system pods — API call failed: {e}")
        return

    infra_pods = [
        p for p in all_pods
        if any(p.metadata.name.startswith(prefix) for prefix in infra_prefixes)
    ]

    if not infra_pods:
        log("No standard control-plane pods found in kube-system (managed control plane?)", "WARN")
        WARNINGS.append(
            "No kube-apiserver/etcd/scheduler pods found in kube-system — "
            "control plane may be managed externally (EKS/GKE/AKS/Rancher hosted)"
        )
        return

    for pod in infra_pods:
        name     = pod.metadata.name
        node     = pod.spec.node_name
        phase    = pod.status.phase
        cs_list  = pod.status.container_statuses or []
        ready    = all(cs.ready for cs in cs_list) if cs_list else (phase == "Running")
        restarts = sum(cs.restart_count for cs in cs_list)

        if phase == "Running" and ready:
            # Pod is healthy right now — restarts are historical, not a current problem
            log(f"OK    {name}  node={node}  Running/Ready  (restarts={restarts})", "OK")
        else:
            # Pod is NOT healthy right now — this is a current infrastructure problem
            reason = phase
            for cs in cs_list:
                if cs.state and cs.state.waiting and cs.state.waiting.reason:
                    reason = cs.state.waiting.reason
                    break
                if cs.state and cs.state.terminated and cs.state.terminated.reason:
                    reason = cs.state.terminated.reason
                    break
            log(f"FAIL  {name}  node={node}  {reason}  (restarts={restarts})", "FAIL")
            IT_ISSUES.append(
                f"Core system pod '{name}' is currently {reason}"
            )


# ─── Check 8: API server reachability ────────────────────────────────────────
def check_apiserver(k8s):
    section("KUBERNETES API SERVER")
    v1 = k8s.CoreV1Api()

    # The kubernetes service in default namespace is the in-cluster API server endpoint
    try:
        svc = v1.read_namespaced_service("kubernetes", "default")
        api_ip   = svc.spec.cluster_ip
        api_port = next(
            (p.port for p in svc.spec.ports if p.name == "https"),
            443
        )
        log(f"INFO  API server ClusterIP: {api_ip}:{api_port}", "INFO")

        # DNS resolution
        ips, elapsed, err = _resolve_with_retry(f"kubernetes.default.svc.{CLUSTER_DOMAIN}")
        if err:
            log(f"FAIL  DNS for kubernetes service: {err}", "FAIL")
            IT_ISSUES.append(f"Cannot resolve kubernetes API service DNS: {err}")
        elif elapsed > DNS_SLOW_THRESHOLD:
            log(f"SLOW  kubernetes service DNS resolved in {elapsed:.3f}s", "WARN")
            IT_ISSUES.append(f"API server DNS slow ({elapsed:.3f}s) — CoreDNS issue")
        else:
            log(f"OK    kubernetes service DNS: {ips}  ({elapsed:.3f}s)", "OK")

        # TCP reachability
        ok, elapsed, err = _tcp_with_retry(api_ip, api_port)
        if ok:
            log(f"OK    TCP connect to API server {api_ip}:{api_port}  ({elapsed:.3f}s)", "OK")
        else:
            log(f"FAIL  TCP connect to API server {api_ip}:{api_port}: {err}", "FAIL")
            IT_ISSUES.append(
                f"Kubernetes API server {api_ip}:{api_port} not reachable via TCP: {err} — "
                "control plane networking issue"
            )

    except Exception as e:
        log(f"WARN  Cannot inspect kubernetes service: {e}", "WARN")
        WARNINGS.append(f"Could not verify API server service: {e}")


# ─── Check 9: Service network path test (infrastructure path only) ────────────
def check_service_network_path(k8s):
    """
    Tests the network infrastructure path for a given service:
      DNS resolution → ClusterIP TCP → Pod IP TCP
    This is a network/infrastructure test — it tells you WHERE in the stack
    the problem is, not whether the application is healthy.
    """
    section(
        f"SERVICE NETWORK PATH TEST  "
        f"{TARGET_SERVICE}.{TARGET_NAMESPACE} :{TARGET_PORT}"
    )
    fqdn = f"{TARGET_SERVICE}.{TARGET_NAMESPACE}.svc.{CLUSTER_DOMAIN}"
    v1   = k8s.CoreV1Api()

    # Step 1 — DNS
    log(f"[1/4] DNS:        {fqdn}")
    dns_ips, dns_elapsed, dns_err = _resolve_with_retry(fqdn)

    if dns_err:
        log(f"      FAIL  {dns_err}  ({dns_elapsed:.3f}s)", "FAIL")
        IT_ISSUES.append(
            f"DNS failed for '{fqdn}': {dns_err} — CoreDNS cannot resolve cluster services"
        )
    elif dns_elapsed > DNS_SLOW_THRESHOLD:
        log(f"      SLOW  {dns_ips}  ({dns_elapsed:.3f}s)", "WARN")
        IT_ISSUES.append(
            f"DNS slow for '{fqdn}': {dns_elapsed:.3f}s — CoreDNS performance problem"
        )
    else:
        log(f"      OK    {dns_ips}  ({dns_elapsed:.3f}s)", "OK")

    # Step 2 — Ground-truth ClusterIP from API
    log(f"[2/4] ClusterIP:  from K8s API (ground truth)")
    api_ip = None
    try:
        svc    = v1.read_namespaced_service(TARGET_SERVICE, TARGET_NAMESPACE)
        api_ip = svc.spec.cluster_ip
        log(f"      OK    ClusterIP = {api_ip}", "OK")
        if dns_ips and api_ip not in dns_ips:
            log(f"      FAIL  DNS returned {dns_ips}, actual is {api_ip}", "FAIL")
            IT_ISSUES.append(
                f"DNS returned wrong IP for '{TARGET_SERVICE}': "
                f"DNS={dns_ips}, actual={api_ip} — stale CoreDNS cache or misconfiguration"
            )
    except Exception as e:
        log(f"      WARN  Cannot read service: {e}", "WARN")
        WARNINGS.append(f"Could not read service '{TARGET_SERVICE}': {e}")

    # Step 3 — TCP via ClusterIP (tests kube-proxy / iptables / ipvs)
    if api_ip:
        log(f"[3/4] ClusterIP TCP:  {api_ip}:{TARGET_PORT}  (tests kube-proxy/ipvs routing)")
        clusterip_ok, elapsed, err = tcp_connect(api_ip, TARGET_PORT)
        if clusterip_ok:
            log(f"      OK    connected  ({elapsed:.3f}s)", "OK")
        else:
            log(f"      FAIL  {err}  ({elapsed:.3f}s)", "FAIL")
            if not dns_err:
                IT_ISSUES.append(
                    f"ClusterIP {api_ip}:{TARGET_PORT} unreachable despite DNS resolving — "
                    "kube-proxy / iptables / ipvs rules are not propagated correctly"
                )
            else:
                IT_ISSUES.append(
                    f"ClusterIP {api_ip}:{TARGET_PORT} unreachable — cluster networking broken"
                )
    else:
        clusterip_ok = False
        log(f"[3/4] ClusterIP TCP:  skipped (ClusterIP unknown)", "INFO")

    # Step 4 — TCP direct to pod IP (tests CNI / pod networking, bypasses everything else)
    log(f"[4/4] Pod IP TCP:  direct to pod IP (tests CNI / pod-to-pod networking)")
    try:
        ep = v1.read_namespaced_endpoints(TARGET_SERVICE, TARGET_NAMESPACE)
        candidates = []
        for subset in (ep.subsets or []):
            ports = [p.port for p in (subset.ports or [])]
            for addr in (subset.addresses or []):
                for port in ports:
                    candidates.append((addr.ip, port))

        if not candidates:
            log("      INFO  No ready endpoints — cannot test pod IP", "INFO")
            WARNINGS.append(
                f"No endpoints for '{TARGET_SERVICE}' — pod IP network test skipped"
            )
        else:
            pod_ip, pod_port = candidates[0]
            pod_ok, elapsed, err = tcp_connect(pod_ip, pod_port)
            if pod_ok:
                log(f"      OK    {pod_ip}:{pod_port}  ({elapsed:.3f}s)", "OK")

                # The critical differential:
                if not clusterip_ok and api_ip:
                    IT_ISSUES.append(
                        f"CRITICAL — Pod IP {pod_ip}:{pod_port} reachable "
                        f"but ClusterIP {api_ip}:{TARGET_PORT} is NOT: "
                        "kube-proxy/iptables/ipvs rules are broken. "
                        "This is the exact signature of a kube-proxy failure."
                    )
                if dns_err:
                    IT_ISSUES.append(
                        f"CRITICAL — Pod IP {pod_ip}:{pod_port} reachable "
                        f"but DNS for '{fqdn}' failed: "
                        "pod networking works but CoreDNS is not functioning. "
                        "This is a DNS-layer infrastructure failure, not an app issue."
                    )
            else:
                log(f"      FAIL  {pod_ip}:{pod_port}  →  {err}", "FAIL")
                IT_ISSUES.append(
                    f"Pod IP {pod_ip}:{pod_port} unreachable directly — "
                    "CNI pod-to-pod networking is broken on this node"
                )

    except Exception as e:
        log(f"      WARN  Cannot test pod IPs: {e}", "WARN")
        WARNINGS.append(f"Pod IP test skipped: {e}")


# ─── Verdict ──────────────────────────────────────────────────────────────────
def print_verdict():
    print(f"\n{'═'*64}", flush=True)

    if IT_ISSUES:
        print("  VERDICT:  ██  IT TEAM / INFRASTRUCTURE RESPONSIBILITY  ██")
        print(f"{'═'*64}")
        print(f"\n  {len(IT_ISSUES)} infrastructure issue(s) found:\n")
        for i, issue in enumerate(IT_ISSUES, 1):
            # Wrap long lines
            words = issue.split()
            line, lines = "", []
            for w in words:
                if len(line) + len(w) + 1 > 70:
                    lines.append(line)
                    line = w
                else:
                    line = f"{line} {w}".strip()
            if line:
                lines.append(line)
            print(f"    {i:2d}. {lines[0]}")
            for continuation in lines[1:]:
                print(f"        {continuation}")
            print()
    else:
        print("  VERDICT:  ██  INFRASTRUCTURE IS HEALTHY  ██")
        print(f"{'═'*64}")
        print("\n  All cluster infrastructure checks passed.")
        print("  If problems persist, they are in the application/deployment layer.")

    if WARNINGS:
        print(f"\n  {'─'*60}")
        print("  Informational / could not verify:\n")
        for w in WARNINGS:
            print(f"    ⚠  {w}")

    print(f"\n{'═'*64}\n", flush=True)
    return 1 if IT_ISSUES else 0


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║       devnopes — Cluster Infrastructure Checker      ║")
    print("║  Checks cluster components only. No app workloads touched.  ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"\n  cluster domain    : {CLUSTER_DOMAIN}")
    print(f"  DNS slow threshold: {DNS_SLOW_THRESHOLD}s")
    print(f"  DNS timeout       : {DNS_TIMEOUT}s")
    print(f"  connect timeout   : {CONNECT_TIMEOUT}s")
    if TARGET_SERVICE:
        print(f"  network path test : {TARGET_SERVICE}.{TARGET_NAMESPACE}:{TARGET_PORT}")
    else:
        print("  network path test : disabled (set TARGET_SERVICE to enable)")

    check_resolv_conf()
    k8s = init_k8s()
    check_cluster_dns(k8s)

    if k8s:
        check_coredns(k8s)
        check_kube_proxy(k8s)
        check_cni(k8s)
        check_nodes(k8s)
        check_system_pods(k8s)
        check_apiserver(k8s)
        if TARGET_SERVICE:
            check_service_network_path(k8s)

    sys.exit(print_verdict())


if __name__ == "__main__":
    main()
