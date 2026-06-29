"""MVP3: top-level cluster status and doctor.

`status` shows cluster node health (reusing the install cluster doctor) plus every Styx pod
service deployed into the cluster: the per-site DuckDNS publisher (a Deployment), the
node-local DNS resolver + the resolv.conf enforcer, and the WireGuard endpoint re-resolver
(all DaemonSets). `doctor` runs the same checks and prints remediation hints. Workload state
is read from the init-server's kubectl over the gateway SSH port, the same path the node
assessment uses.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .cluster_dns import ENFORCER_APP, RESOLVER_APP
from .dns_publish import DUCKDNS_APP, STYX_NAMESPACE
from .reresolve import RERESOLVE_APP

# Each Styx pod service we surface: (report key, human label, app.kubernetes.io/name label,
# kubectl kind, the command that deploys it). Order is the natural deploy order.
_WORKLOAD_SPECS: tuple[tuple[str, str, str, str, str], ...] = (
    ("duckdns", "DuckDNS publisher", DUCKDNS_APP, "Deployment", "styxctl deploy dns apply"),
    ("resolver", "DNS resolver", RESOLVER_APP, "DaemonSet", "styxctl deploy resolver apply"),
    ("enforcer", "resolv.conf enforcer", ENFORCER_APP, "DaemonSet", "styxctl deploy resolver apply (force: true)"),
    ("reresolve", "WG reresolver", RERESOLVE_APP, "DaemonSet", "styxctl deploy reresolve apply"),
)


def _deployment_counts(item: dict[str, Any]) -> tuple[int, int]:
    status = item.get("status", {}) or {}
    spec = item.get("spec", {}) or {}
    ready = int(status.get("readyReplicas", 0) or 0)
    desired = int(status.get("replicas", 0) or spec.get("replicas", 0) or 0)
    return ready, desired


def _daemonset_counts(item: dict[str, Any]) -> tuple[int, int]:
    status = item.get("status", {}) or {}
    ready = int(status.get("numberReady", 0) or 0)
    desired = int(status.get("desiredNumberScheduled", 0) or 0)
    return ready, desired


def summarize_styx_workloads(items: Any) -> dict[str, Any]:
    """Pure: turn kubectl `items` (mixed Deployments + DaemonSets) into a per-service report.

    Each service entry is ``{present, ready, desired, instances, detail}``. A service with no
    matching object is reported absent with a deploy hint. No cluster access — the SSH/kubectl
    plumbing lives in ``collect_styx_workloads``; this is the testable core.
    """
    by_app: dict[str, list[dict[str, Any]]] = {}
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        labels = (item.get("metadata", {}) or {}).get("labels", {}) or {}
        name = labels.get("app.kubernetes.io/name")
        if isinstance(name, str):
            by_app.setdefault(name, []).append(item)

    workloads: dict[str, Any] = {"namespace": STYX_NAMESPACE}
    for key, _label, app, kind, deploy_cmd in _WORKLOAD_SPECS:
        matched = by_app.get(app, [])
        if not matched:
            workloads[key] = {
                "present": False,
                "instances": 0,
                "ready": 0,
                "desired": 0,
                "detail": f"not deployed (run: {deploy_cmd})",
            }
            continue
        ready = desired = 0
        counts = _deployment_counts if kind == "Deployment" else _daemonset_counts
        for obj in matched:
            obj_ready, obj_desired = counts(obj)
            ready += obj_ready
            desired += obj_desired
        if key == "duckdns":
            unit = f"{len(matched)} site publisher{'s' if len(matched) != 1 else ''}, "
        else:
            unit = ""
        workloads[key] = {
            "present": True,
            "instances": len(matched),
            "ready": ready,
            "desired": desired,
            "detail": f"{unit}{ready}/{desired} ready",
        }
    return workloads


def collect_styx_workloads(config_path: str | Path | None = None) -> dict[str, Any]:
    """Report every Styx pod service deployed in the cluster (read via the init-server's kubectl)."""
    from .config import find_config, load_config
    from .install import _election_context
    from .inventory import collect_inventory
    from .k3s_cluster import _run_ssh_command, _ssh_target
    from .lan_election import resolve_lan_leadership
    from .nodes import identify_local_node, init_server_node, parse_nodes

    config = load_config(config_path) if config_path else load_config(find_config())
    inventory = collect_inventory()
    effective_config, election = resolve_lan_leadership(config, inventory)
    nodes = parse_nodes(effective_config)
    init = init_server_node(nodes)
    if init is None:
        workloads = summarize_styx_workloads([])
        workloads["detail"] = "no init-server node in config"
        return workloads

    local_node = identify_local_node(nodes, inventory, effective_config)
    election_lan_ips, election_leader = _election_context(election)
    connection = _ssh_target(
        init,
        None,
        effective_config,
        inventory=inventory,
        local_node=local_node,
        election_lan_ips=election_lan_ips,
        election_leader=election_leader,
    )
    ok, detail = _run_ssh_command(
        connection.target,
        f"sudo kubectl -n {STYX_NAMESPACE} get deploy,daemonset "
        f"-l app.kubernetes.io/managed-by=styxctl -o json 2>/dev/null",
        port=connection.port,
        jump=connection.jump,
    )
    if not ok:
        workloads = summarize_styx_workloads([])
        workloads["detail"] = "could not reach the init-server's kubectl (is the cluster up?)"
        return workloads
    items: list[Any] = []
    if detail.strip():
        try:
            items = json.loads(detail).get("items", [])
        except (json.JSONDecodeError, ValueError):
            workloads = summarize_styx_workloads([])
            workloads["detail"] = "could not parse kubectl output"
            return workloads
    return summarize_styx_workloads(items)


def run_status(config_path: str | Path | None = None) -> dict[str, Any]:
    """Cluster node health (install cluster doctor) plus every deployed Styx pod service."""
    from .install import run_cluster_doctor

    health = run_cluster_doctor(config_path=config_path)
    health["workloads"] = collect_styx_workloads(config_path)
    return health


def run_doctor(config_path: str | Path | None = None) -> tuple[dict[str, Any], int]:
    """Status plus remediation hints; exits non-zero when the cluster is unhealthy."""
    status = run_status(config_path)
    hints: list[str] = []

    workloads = status.get("workloads", {})
    for key, label, app, kind, deploy_cmd in _WORKLOAD_SPECS:
        w = workloads.get(key, {})
        if not w.get("present"):
            hints.append(f"{label} not deployed — run `{deploy_cmd}` on the init-server.")
        elif w.get("ready", 0) < w.get("desired", 1):
            hints.append(
                f"{label} degraded ({w.get('detail')}) — inspect: "
                f"kubectl -n {STYX_NAMESPACE} get {kind.lower()} -l app.kubernetes.io/name={app}"
            )
    for issue in status.get("issues", []):
        hints.append(f"{issue}")

    status["hints"] = hints
    # Node-level issues mean the cluster itself is unhealthy → non-zero. A missing optional
    # workload is only a hint, not a failure.
    exit_code = 1 if status.get("issues") else 0
    return status, exit_code
