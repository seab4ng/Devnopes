#!/usr/bin/env python3
"""
k8s-diagnostics: Cluster vs Deployment Issue Differentiator
Runs as a K8s Job and determines whether observed problems are:
  - IT TEAM responsibility  (cluster infra: DNS, CNI, kube-proxy, nodes)
  - DEVOPS responsibility   (deployment:    bad image, wrong selector, missing config)
"""

import os
import sys
import time
import socket
import threading
from datetime import datetime, timezone

# ─── Configuration (override via env vars in the Job manifest) ────────────────
TARGET_NAMESPACE    = os.environ.get("TARGET_NAMESPACE",    "default")
TARGET_SERVICE      = os.environ.get("TARGET_SERVICE",      "")   # specific svc to deep-test
TARGET_PORT         = int(os.environ.get("TARGET_PORT",     "80"))
CLUSTER_DOMAIN      = os.environ.get("CLUSTER_DOMAIN",      "cluster.local")
DNS_SLOW_THRESHOLD  = float(os.environ.get("DNS_SLOW_THRESHOLD", "0.5"))   # seconds
DNS_TIMEOUT         = float(os.environ.get("DNS_TIMEOUT",   "3.0"))
CONNECT_TIMEOUT     = float(os.environ.get("CONNECT_TIMEOUT","3.0"))

# ─── Finding buckets ─────────────────────────────────────────────────────────
IT_ISSUES     = []   # cluster/infra problems  → IT Team
DEVOPS_ISSUES = []   # deployment/config problems → DevOps
WARNINGS      = []   # informational / ambiguous

# ─── Helpers ─────────────────────────────────────────────────────────────────
def ts():
    return datetime.now().strftime("%H:%M:%S")

ICONS = {"OK": "✓", "FAIL": "✗", "WARN": "⚠", "INFO": "·"}

def log(msg, level="INFO"):
    icon = ICONS.get(level, "·")
    print(f"[{ts()}] {icon} {msg}", flush=True)

def section(title):
    print(f"\n{'─'*62}", flush=True)
    print(f"  {title}", flush=True)
    print(f"{'─'*62}", flush=True)


# ─── Network primitives ───────────────────────────────────────────────────────
def resolve_with_timing(hostname, timeout=None):
    """
    Returns (ip_list, elapsed_seconds, error_string).
    Uses a daemon thread so we can enforce a hard timeout on getaddrinfo.
    """
    timeout = timeout or DNS_TIMEOUT
    ips, err = [None], [None]

    def _work():
        try:
            results = socket.getaddrinfo(hostname, None, socket.AF_INET)
            ips[0] = list(dict.fromkeys(r[4][0] for r in results))  # dedup, preserve order
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


# ─── K8s client setup ─────────────────────────────────────────────────────────
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


# ─── Check 1: Pod DNS resolver config ────────────────────────────────────────
def check_resolv_conf():
    section("POD DNS RESOLVER CONFIG  (/etc/resolv.conf)")
    try:
        with open("/etc/resolv.conf") as f:
            lines = f.read().strip().splitlines()
        nameservers = [l.split()[1] for l in lines if l.startswith("nameserver")]
        search_domains = next((l.split()[1:] for l in lines if l.startswith("search")), [])
        options = next((l for l in lines if l.startswith("options")), None)

        for ns in nameservers:
            log(f"nameserver : {ns}", "INFO")
        log(f"search     : {' '.join(search_domains)}", "INFO")
        if options:
            log(f"options    : {options}", "INFO")

        if not nameservers:
            log("No nameserver entries — DNS is broken at pod level", "FAIL")
            IT_ISSUES.append("No nameserver in /etc/resolv.conf — pod has no DNS resolver configured")

        return nameservers
    except Exception as e:
        log(f"Cannot read /etc/resolv.conf: {e}", "WARN")
        return []


# ─── Check 2: Core cluster DNS names ─────────────────────────────────────────
def check_cluster_dns():
    section("CLUSTER DNS RESOLUTION")

    core_names = [
        f"kubernetes.default.svc.{CLUSTER_DOMAIN}",     # must always resolve
        f"kube-dns.kube-system.svc.{CLUSTER_DOMAIN}",   # CoreDNS service itself
        "kubernetes",                                    # short-name resolution
    ]

    dns_ok = True
    for name in core_names:
        ips, elapsed, err = resolve_with_timing(name)
        if err:
            log(f"FAIL  {name}  →  {err}", "FAIL")
            IT_ISSUES.append(
                f"DNS resolution failed for '{name}': {err} "
                f"→ CoreDNS is not functioning"
            )
            dns_ok = False
        elif elapsed > DNS_SLOW_THRESHOLD:
            log(f"SLOW  {name}  →  {ips}  ({elapsed:.3f}s  >  {DNS_SLOW_THRESHOLD}s)", "WARN")
            IT_ISSUES.append(
                f"DNS slow: '{name}' resolved in {elapsed:.3f}s (threshold {DNS_SLOW_THRESHOLD}s) "
                f"→ CoreDNS overloaded, misconfigured, or upstream forwarder unreachable"
            )
            dns_ok = False
        else:
            log(f"OK    {name}  →  {ips}  ({elapsed:.3f}s)", "OK")

    # NXDOMAIN sanity check — proves DNS is actually answering, not silently timing out
    nxname = f"nxdomain-check-xyzabc.kube-system.svc.{CLUSTER_DOMAIN}"
    ips, elapsed, err = resolve_with_timing(nxname, timeout=DNS_TIMEOUT)
    if ips:
        log(f"WARN  NXDOMAIN test returned IPs {ips} — wildcard DNS active?", "WARN")
        WARNINGS.append("Wildcard DNS detected — resolution failures may be masked")
    else:
        log(f"OK    NXDOMAIN test: non-existent name correctly not resolved ({elapsed:.3f}s)", "OK")

    return dns_ok


# ─── Check 3: CoreDNS pod health ─────────────────────────────────────────────
def check_coredns(k8s):
    section("COREDNS PODS  (kube-system)")
    v1 = k8s.CoreV1Api()

    # Try both common label selectors
    pods = []
    for selector in ("k8s-app=kube-dns", "app=coredns", "app.kubernetes.io/name=coredns"):
        pods = v1.list_namespaced_pod("kube-system", label_selector=selector).items
        if pods:
            break

    if not pods:
        log("No CoreDNS/kube-dns pods found in kube-system", "FAIL")
        IT_ISSUES.append("CRITICAL: No CoreDNS/kube-dns pods in kube-system — cluster DNS is absent")
        return

    for pod in pods:
        name = pod.metadata.name
        node = pod.spec.node_name
        phase = pod.status.phase
        container_statuses = pod.status.container_statuses or []
        ready = all(cs.ready for cs in container_statuses)
        restarts = sum(cs.restart_count for cs in container_statuses)

        if phase == "Running" and ready:
            if restarts > 10:
                log(f"WARN  {name} on {node}: Running but {restarts} restarts", "WARN")
                IT_ISSUES.append(
                    f"CoreDNS pod '{name}' has {restarts} restarts → DNS instability / recurring crashes"
                )
            else:
                log(f"OK    {name} on {node}: Running/Ready  ({restarts} restarts)", "OK")
        else:
            reason = phase
            for cs in container_statuses:
                if cs.state and cs.state.waiting and cs.state.waiting.reason:
                    reason = cs.state.waiting.reason
                    break
            log(f"FAIL  {name} on {node}: {reason}  ({restarts} restarts)", "FAIL")
            IT_ISSUES.append(f"CoreDNS pod '{name}' not healthy: {reason}")


# ─── Check 4: kube-proxy + CNI ───────────────────────────────────────────────
def check_network_components(k8s):
    section("KUBE-PROXY + CNI DAEMONSETS")
    apps = k8s.AppsV1Api()
    v1   = k8s.CoreV1Api()

    # kube-proxy
    try:
        ds = apps.read_namespaced_daemon_set("kube-proxy", "kube-system")
        desired = ds.status.desired_number_scheduled or 0
        ready   = ds.status.number_ready or 0
        if ready < desired:
            log(f"FAIL  kube-proxy: {ready}/{desired} pods ready", "FAIL")
            IT_ISSUES.append(
                f"kube-proxy: {ready}/{desired} pods ready → "
                f"ClusterIP/NodePort routing broken on some nodes"
            )
        else:
            log(f"OK    kube-proxy: {ready}/{desired} pods ready", "OK")
    except Exception as e:
        status = getattr(e, "status", None)
        if status == 404:
            log("INFO  kube-proxy daemonset not found — cluster may use eBPF dataplane (Cilium/Calico eBPF)", "INFO")
            WARNINGS.append("kube-proxy not found; eBPF dataplane assumed")
        else:
            log(f"WARN  Cannot read kube-proxy daemonset: {e}", "WARN")

    # CNI — try common labels
    cni_candidates = [
        ("k8s-app=calico-node",           "Calico"),
        ("app=flannel",                   "Flannel"),
        ("k8s-app=flannel",               "Flannel"),
        ("app=cilium",                    "Cilium"),
        ("name=weave-net",                "Weave"),
        ("app=canal",                     "Canal"),
        ("app=antrea-agent",              "Antrea"),
        ("app.kubernetes.io/name=calico", "Calico"),
    ]

    cni_found = False
    for selector, cni_name in cni_candidates:
        try:
            pods = v1.list_namespaced_pod("kube-system", label_selector=selector).items
            if not pods:
                continue
            cni_found = True
            bad = [p for p in pods if not all(
                cs.ready for cs in (p.status.container_statuses or [])
            )]
            if bad:
                for p in bad:
                    reason = p.status.phase
                    for cs in (p.status.container_statuses or []):
                        if cs.state and cs.state.waiting and cs.state.waiting.reason:
                            reason = cs.state.waiting.reason
                            break
                    log(f"FAIL  {cni_name} pod {p.metadata.name}: {reason}", "FAIL")
                    IT_ISSUES.append(
                        f"CNI ({cni_name}) pod '{p.metadata.name}' not healthy: {reason} "
                        f"→ pod networking broken on that node"
                    )
            else:
                log(f"OK    {cni_name}: {len(pods)}/{len(pods)} pods ready", "OK")
            break
        except Exception:
            continue

    if not cni_found:
        log("WARN  No CNI pods detected with known labels", "WARN")
        WARNINGS.append("CNI pods not found with known labels — verify CNI manually")


# ─── Check 5: Node conditions ─────────────────────────────────────────────────
def check_nodes(k8s):
    section("NODE CONDITIONS")
    v1 = k8s.CoreV1Api()
    nodes = v1.list_node().items

    for node in nodes:
        name = node.metadata.name
        cond_map = {c.type: c.status for c in node.status.conditions}

        problems = []
        if cond_map.get("Ready") != "True":
            problems.append("NotReady")
        if cond_map.get("NetworkUnavailable") == "True":
            problems.append("NetworkUnavailable")
        if cond_map.get("MemoryPressure") == "True":
            problems.append("MemoryPressure")
        if cond_map.get("DiskPressure") == "True":
            problems.append("DiskPressure")

        if problems:
            log(f"FAIL  {name}: {', '.join(problems)}", "FAIL")
            for p in problems:
                IT_ISSUES.append(f"Node '{name}' condition: {p}")
        else:
            log(f"OK    {name}: Ready", "OK")


# ─── Check 6: Deployments and pods in target namespace ───────────────────────
def check_deployments(k8s):
    section(f"DEPLOYMENTS + PODS  (namespace: {TARGET_NAMESPACE})")
    apps = k8s.AppsV1Api()
    v1   = k8s.CoreV1Api()

    deployments = apps.list_namespaced_deployment(TARGET_NAMESPACE).items
    if not deployments:
        log(f"No deployments found in namespace '{TARGET_NAMESPACE}'", "WARN")
        WARNINGS.append(
            f"No deployments in '{TARGET_NAMESPACE}' — wrong namespace? Helm release not installed?"
        )
        return

    for dep in deployments:
        dname   = dep.metadata.name
        desired = dep.spec.replicas or 0
        ready   = dep.status.ready_replicas or 0

        if ready >= desired:
            log(f"OK    {dname}: {ready}/{desired} replicas ready", "OK")
            continue

        log(f"FAIL  {dname}: {ready}/{desired} replicas ready — investigating pods...", "FAIL")

        # Dig into pods
        label_sel = ",".join(
            f"{k}={v}" for k, v in (dep.spec.selector.match_labels or {}).items()
        )
        pods = v1.list_namespaced_pod(TARGET_NAMESPACE, label_selector=label_sel).items

        for pod in pods:
            pname = pod.metadata.name
            phase = pod.status.phase

            for cs in (pod.status.container_statuses or []):
                if cs.ready:
                    continue
                restarts = cs.restart_count

                if cs.state and cs.state.waiting:
                    reason = cs.state.waiting.reason or "Unknown"
                    msg    = cs.state.waiting.message or ""

                    if reason in ("ImagePullBackOff", "ErrImagePull", "InvalidImageName"):
                        DEVOPS_ISSUES.append(
                            f"Pod '{pname}' container '{cs.name}': {reason} "
                            f"(image: {cs.image}) — wrong image tag or registry unreachable in airgap"
                        )
                    elif reason == "CrashLoopBackOff":
                        DEVOPS_ISSUES.append(
                            f"Pod '{pname}' container '{cs.name}': CrashLoopBackOff ({restarts} restarts) "
                            f"— application crashes on startup; check app config/secrets/logs"
                        )
                    elif reason == "CreateContainerConfigError":
                        DEVOPS_ISSUES.append(
                            f"Pod '{pname}' container '{cs.name}': CreateContainerConfigError "
                            f"— missing Secret or ConfigMap referenced in deployment"
                        )
                    elif reason == "OOMKilled":
                        DEVOPS_ISSUES.append(
                            f"Pod '{pname}' container '{cs.name}': OOMKilled "
                            f"— memory limit too low; increase resources in Helm values"
                        )
                    elif reason in ("ContainerCreating", "PodInitializing"):
                        pass  # transient
                    else:
                        DEVOPS_ISSUES.append(
                            f"Pod '{pname}' container '{cs.name}': {reason} — {msg}"
                        )

                elif cs.state and cs.state.terminated:
                    exit_code = cs.state.terminated.exit_code
                    treason   = cs.state.terminated.reason or f"exit {exit_code}"
                    if exit_code != 0:
                        DEVOPS_ISSUES.append(
                            f"Pod '{pname}' container '{cs.name}': terminated ({treason}) "
                            f"— non-zero exit; check application logs"
                        )


# ─── Check 7: Service endpoints ──────────────────────────────────────────────
def check_services_and_endpoints(k8s):
    section(f"SERVICES + ENDPOINTS  (namespace: {TARGET_NAMESPACE})")
    v1 = k8s.CoreV1Api()

    services = v1.list_namespaced_service(TARGET_NAMESPACE).items
    if not services:
        log(f"No services in namespace '{TARGET_NAMESPACE}'", "WARN")
        return

    for svc in services:
        if svc.spec.type == "ExternalName":
            continue
        sname      = svc.metadata.name
        cluster_ip = svc.spec.cluster_ip

        try:
            ep = v1.read_namespaced_endpoints(sname, TARGET_NAMESPACE)
            ready_addrs = []
            for subset in (ep.subsets or []):
                ready_addrs.extend(subset.addresses or [])

            if not ready_addrs:
                log(f"FAIL  Service '{sname}' ({cluster_ip}): 0 ready endpoints", "FAIL")
                DEVOPS_ISSUES.append(
                    f"Service '{sname}' has no ready endpoints — "
                    f"pod selector does not match any running pod labels, "
                    f"or all backing pods are unhealthy"
                )
            else:
                pod_ips = [a.ip for a in ready_addrs]
                log(f"OK    Service '{sname}' ({cluster_ip}): {len(pod_ips)} endpoint(s) {pod_ips}", "OK")
        except Exception as e:
            log(f"WARN  Cannot read endpoints for '{sname}': {e}", "WARN")


# ─── Check 8: Resource quotas ─────────────────────────────────────────────────
def check_resource_quotas(k8s):
    v1 = k8s.CoreV1Api()
    try:
        quotas = v1.list_namespaced_resource_quota(TARGET_NAMESPACE).items
    except Exception:
        return
    if not quotas:
        return

    section(f"RESOURCE QUOTAS  (namespace: {TARGET_NAMESPACE})")
    for quota in quotas:
        hard = quota.status.hard or {}
        used = quota.status.used or {}
        for resource in ("pods", "requests.cpu", "requests.memory", "limits.cpu", "limits.memory"):
            if resource not in hard:
                continue
            h, u = hard[resource], used.get(resource, "0")
            log(f"INFO  {quota.metadata.name} — {resource}: used={u}  limit={h}", "INFO")
            if resource == "pods":
                try:
                    if int(u) >= int(h):
                        log(f"FAIL  Pod quota EXHAUSTED: {u}/{h}", "FAIL")
                        DEVOPS_ISSUES.append(
                            f"ResourceQuota '{quota.metadata.name}': pod limit reached ({u}/{h}) "
                            f"— new pods cannot be scheduled"
                        )
                except ValueError:
                    pass


# ─── Check 9: Target service deep-test (DNS vs ClusterIP vs Pod IP) ──────────
def check_target_service(k8s):
    if not TARGET_SERVICE:
        return

    section(f"SERVICE DEEP-TEST  →  {TARGET_SERVICE}.{TARGET_NAMESPACE}  port {TARGET_PORT}")
    fqdn = f"{TARGET_SERVICE}.{TARGET_NAMESPACE}.svc.{CLUSTER_DOMAIN}"
    v1   = k8s.CoreV1Api()

    # ── Step 1: DNS ──────────────────────────────────────────────────────────
    log(f"[1/4] DNS resolution: {fqdn}")
    dns_ips, dns_elapsed, dns_err = resolve_with_timing(fqdn)

    if dns_err:
        log(f"      FAIL  {dns_err}  ({dns_elapsed:.3f}s)", "FAIL")
        IT_ISSUES.append(f"Service DNS '{fqdn}' not resolvable: {dns_err}")
    elif dns_elapsed > DNS_SLOW_THRESHOLD:
        log(f"      SLOW  {dns_ips}  ({dns_elapsed:.3f}s  >  {DNS_SLOW_THRESHOLD}s)", "WARN")
        IT_ISSUES.append(
            f"DNS slow for '{fqdn}': {dns_elapsed:.3f}s — CoreDNS performance issue"
        )
    else:
        log(f"      OK    {dns_ips}  ({dns_elapsed:.3f}s)", "OK")

    # ── Step 2: K8s API ClusterIP (ground truth) ──────────────────────────────
    log(f"[2/4] ClusterIP from K8s API")
    api_cluster_ip = None
    try:
        svc = v1.read_namespaced_service(TARGET_SERVICE, TARGET_NAMESPACE)
        api_cluster_ip = svc.spec.cluster_ip
        log(f"      OK    ClusterIP = {api_cluster_ip}", "OK")

        if dns_ips and api_cluster_ip not in dns_ips:
            log(f"      FAIL  DNS returned {dns_ips} but actual ClusterIP is {api_cluster_ip}", "FAIL")
            IT_ISSUES.append(
                f"DNS returned wrong IP for '{TARGET_SERVICE}': "
                f"DNS={dns_ips}, actual={api_cluster_ip} → stale CoreDNS cache or misconfiguration"
            )
    except Exception as e:
        log(f"      WARN  Cannot read service: {e}", "WARN")

    # ── Step 3: TCP via ClusterIP ─────────────────────────────────────────────
    if api_cluster_ip:
        log(f"[3/4] TCP connect via ClusterIP  {api_cluster_ip}:{TARGET_PORT}")
        clusterip_ok, elapsed, err = tcp_connect(api_cluster_ip, TARGET_PORT)
        if clusterip_ok:
            log(f"      OK    connected  ({elapsed:.3f}s)", "OK")
        else:
            log(f"      FAIL  {err}  ({elapsed:.3f}s)", "FAIL")
            if not dns_err:
                IT_ISSUES.append(
                    f"Service '{TARGET_SERVICE}': DNS resolves to {dns_ips} but "
                    f"ClusterIP {api_cluster_ip}:{TARGET_PORT} is unreachable "
                    f"→ kube-proxy/iptables rules not propagated"
                )
            else:
                IT_ISSUES.append(
                    f"Service '{TARGET_SERVICE}': both DNS and ClusterIP unreachable "
                    f"→ cluster networking is broken"
                )
    else:
        clusterip_ok = False

    # ── Step 4: TCP direct to pod IP ─────────────────────────────────────────
    log(f"[4/4] TCP connect directly to pod IP (bypasses DNS + kube-proxy)")
    try:
        ep = v1.read_namespaced_endpoints(TARGET_SERVICE, TARGET_NAMESPACE)
        pod_candidates = []
        for subset in (ep.subsets or []):
            ports = [p.port for p in (subset.ports or [])]
            for addr in (subset.addresses or []):
                for port in ports:
                    pod_candidates.append((addr.ip, port))

        if not pod_candidates:
            log("      WARN  No ready endpoints — cannot test pod IP", "WARN")
        else:
            pod_ip, pod_port = pod_candidates[0]
            pod_ok, elapsed, err = tcp_connect(pod_ip, pod_port)
            if pod_ok:
                log(f"      OK    {pod_ip}:{pod_port}  ({elapsed:.3f}s)", "OK")
                if not clusterip_ok and api_cluster_ip:
                    # THE KEY FINDING: pod works, service routing doesn't
                    IT_ISSUES.append(
                        f"CRITICAL: Pod IP {pod_ip}:{pod_port} is reachable but "
                        f"ClusterIP {api_cluster_ip}:{TARGET_PORT} is not "
                        f"→ kube-proxy is failing to set iptables/ipvs rules"
                    )
                if dns_err:
                    IT_ISSUES.append(
                        f"CRITICAL: Pod IP {pod_ip}:{pod_port} is reachable but "
                        f"DNS for '{fqdn}' failed "
                        f"→ CoreDNS is not working (pod networking is fine)"
                    )
            else:
                log(f"      FAIL  {pod_ip}:{pod_port}  →  {err}", "FAIL")
                IT_ISSUES.append(
                    f"Pod IP {pod_ip}:{pod_port} unreachable directly "
                    f"→ CNI/pod-to-pod networking is broken"
                )
    except Exception as e:
        log(f"      WARN  Cannot test pod IPs: {e}", "WARN")


# ─── Check 10: Recent warning events ─────────────────────────────────────────
def check_events(k8s):
    section(f"RECENT WARNING EVENTS  (namespace: {TARGET_NAMESPACE})")
    v1 = k8s.CoreV1Api()
    try:
        events = v1.list_namespaced_event(
            TARGET_NAMESPACE, field_selector="type=Warning"
        ).items
    except Exception as e:
        log(f"Cannot read events: {e}", "WARN")
        return

    epoch = datetime.min.replace(tzinfo=timezone.utc)
    events.sort(key=lambda e: e.last_timestamp or epoch, reverse=True)

    shown = 0
    for ev in events[:10]:
        obj    = f"{ev.involved_object.kind}/{ev.involved_object.name}"
        count  = ev.count or 1
        log(f"  [{ev.last_timestamp}] {obj}: {ev.reason} ({count}x) — {ev.message}", "WARN")
        shown += 1

    if shown == 0:
        log("  No recent warning events", "OK")


# ─── Final verdict ────────────────────────────────────────────────────────────
def print_verdict():
    has_it     = bool(IT_ISSUES)
    has_devops = bool(DEVOPS_ISSUES)

    print(f"\n{'═'*62}", flush=True)

    if has_it:
        print("  VERDICT: ██  IT TEAM / INFRASTRUCTURE RESPONSIBILITY  ██")
        print(f"{'═'*62}")
        print("\n  Cluster/infrastructure issues found:\n")
        for i, issue in enumerate(IT_ISSUES, 1):
            print(f"    {i:2d}. {issue}")
        if has_devops:
            print("\n  DevOps issues also present (resolve IT issues first):\n")
            for i, issue in enumerate(DEVOPS_ISSUES, 1):
                print(f"    {i:2d}. {issue}")
    elif has_devops:
        print("  VERDICT: ██  DEVOPS / DEPLOYMENT RESPONSIBILITY  ██")
        print(f"{'═'*62}")
        print("\n  Deployment/configuration issues found:\n")
        for i, issue in enumerate(DEVOPS_ISSUES, 1):
            print(f"    {i:2d}. {issue}")
    else:
        print("  VERDICT: ██  ALL CHECKS PASSED — NO ISSUES DETECTED  ██")
        print(f"{'═'*62}")
        print("\n  Cluster health and deployment health look good.")

    if WARNINGS:
        print("\n  Informational warnings:\n")
        for w in WARNINGS:
            print(f"    ⚠  {w}")

    print(f"\n{'═'*62}\n", flush=True)
    return 1 if (has_it or has_devops) else 0


# ─── Entry point ──────────────────────────────────────────────────────────────
def main():
    print("╔══════════════════════════════════════════════════════════╗")
    print("║        k8s-diagnostics  —  Cluster Issue Classifier     ║")
    print("║   Determines: IT Team (infra) vs DevOps (deployment)    ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"\n  target namespace  : {TARGET_NAMESPACE}")
    print(f"  target service    : {TARGET_SERVICE or '(none — set TARGET_SERVICE to deep-test)'}")
    print(f"  cluster domain    : {CLUSTER_DOMAIN}")
    print(f"  DNS slow threshold: {DNS_SLOW_THRESHOLD}s")
    print(f"  connect timeout   : {CONNECT_TIMEOUT}s\n")

    check_resolv_conf()
    check_cluster_dns()

    k8s = init_k8s()
    if k8s:
        check_coredns(k8s)
        check_network_components(k8s)
        check_nodes(k8s)
        check_deployments(k8s)
        check_services_and_endpoints(k8s)
        check_resource_quotas(k8s)
        if TARGET_SERVICE:
            check_target_service(k8s)
        check_events(k8s)

    sys.exit(print_verdict())


if __name__ == "__main__":
    main()
