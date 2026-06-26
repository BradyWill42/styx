"""MVP3: top-level cluster status and doctor.

`status` shows cluster node health (reusing the install cluster doctor) plus the Styx
workloads deployed into the cluster — currently the DuckDNS publisher. `doctor` runs the
same checks and reports remediation hints. The workload state is read from the
init-server's kubectl over the gateway SSH port, the same path the node assessment uses.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .dns_publish import DUCKDNS_DEPLOYMENT, STYX_NAMESPACE


def collect_styx_workloads(config_path: str | Path | None = None) -> dict[str, Any]:
    """Report Styx workloads deployed in the cluster (the DuckDNS publisher today)."""
    from .config import find_config, load_config
    from .install import _election_context
    from .inventory import collect_inventory
    from .k3s_cluster import _run_ssh_command, _ssh_target
    from .lan_election import resolve_lan_leadership
    from .nodes import identify_local_node, init_server_node, parse_nodes

    duckdns: dict[str, Any] = {"present": False, "detail": "not checked"}
    workloads: dict[str, Any] = {"namespace": STYX_NAMESPACE, "duckdns": duckdns}

    config = load_config(config_path) if config_path else load_config(find_config())
    inventory = collect_inventory()
    effective_config, election = resolve_lan_leadership(config, inventory)
    nodes = parse_nodes(effective_config)
    init = init_server_node(nodes)
    if init is None:
        duckdns["detail"] = "no init-server node in config"
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
        f"sudo kubectl -n {STYX_NAMESPACE} get deployment {DUCKDNS_DEPLOYMENT} -o json 2>/dev/null",
        port=connection.port,
        jump=connection.jump,
    )
    if not ok or not detail.strip():
        duckdns["detail"] = "not deployed (run: styxctl deploy dns apply)"
        return workloads
    try:
        data = json.loads(detail)
        status = data.get("status", {})
        ready = int(status.get("readyReplicas", 0) or 0)
        desired = int(status.get("replicas", 0) or data.get("spec", {}).get("replicas", 0) or 0)
        duckdns.update({"present": True, "ready": ready, "desired": desired, "detail": f"{ready}/{desired} ready"})
    except (json.JSONDecodeError, ValueError):
        duckdns["detail"] = "could not parse kubectl output"
    return workloads


def run_status(config_path: str | Path | None = None) -> dict[str, Any]:
    """Cluster node health (install cluster doctor) plus deployed Styx workloads."""
    from .install import run_cluster_doctor

    health = run_cluster_doctor(config_path=config_path)
    health["workloads"] = collect_styx_workloads(config_path)
    return health


def run_doctor(config_path: str | Path | None = None) -> tuple[dict[str, Any], int]:
    """Status plus remediation hints; exits non-zero when the cluster is unhealthy."""
    status = run_status(config_path)
    hints: list[str] = []

    duckdns = status.get("workloads", {}).get("duckdns", {})
    if not duckdns.get("present"):
        hints.append("DuckDNS publisher is not deployed — run `styxctl deploy dns apply` on the init-server.")
    elif duckdns.get("ready", 0) < duckdns.get("desired", 1):
        hints.append(
            f"DuckDNS publisher degraded ({duckdns.get('detail')}) — "
            f"inspect: kubectl -n {STYX_NAMESPACE} describe deploy/{DUCKDNS_DEPLOYMENT}"
        )
    for issue in status.get("issues", []):
        hints.append(f"{issue}")

    status["hints"] = hints
    # Node-level issues mean the cluster itself is unhealthy → non-zero. A missing optional
    # workload is only a hint, not a failure.
    exit_code = 1 if status.get("issues") else 0
    return status, exit_code
