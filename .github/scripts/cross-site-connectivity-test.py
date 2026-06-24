#!/usr/bin/env python3
"""Real cross-site connectivity from thor to the pegasus/atlas hub."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = Path("reports/styx/runner-integration/cross-site.json")

sys.path.insert(0, str(REPO_ROOT / ".github" / "scripts"))
from runner_config import prepare_styx_yaml  # noqa: E402


def _prepare_styx_yaml() -> None:
    prepare_styx_yaml(REPO_ROOT)


def main() -> int:
    runner_name = os.environ.get("RUNNER_NAME", "thor")
    if runner_name != "thor":
        print(f"SKIP: cross-site test runs on thor, not {runner_name}")
        return 0

    print("=== Cross-site connectivity (thor -> hub) ===")
    _prepare_styx_yaml()

    from styxctl.bootstrap_config import effective_ssh_port, load_operational_config
    from styxctl.gateway import parse_gateway_ports
    from styxctl.install import run_lan_election_preview
    from styxctl.inventory import collect_inventory
    from styxctl.k3s_cluster import _node_ssh_connection, _run_ssh_command
    from styxctl.nodes import identify_local_node, parse_nodes, site_entrypoint_for

    inventory = collect_inventory()
    config = load_operational_config(REPO_ROOT / "styx.yaml", inventory=inventory)
    nodes = parse_nodes(config)
    local_node = identify_local_node(nodes, inventory, config)
    gateway = parse_gateway_ports(config)
    ssh_port = effective_ssh_port(config, gateway.ssh)
    by_name = {node.name: node for node in nodes}

    checks: list[dict[str, object]] = []

    if local_node is None or local_node.name != "thor":
        print(
            f"WARN: thor cross-site test running on unidentified host "
            f"({inventory.hostname}); continuing with configured routes",
            file=sys.stderr,
        )

    _, election_code = run_lan_election_preview(config_path=REPO_ROOT / "styx.yaml")
    election_report_path = REPO_ROOT / "reports/styx/lan-election-plan.json"
    election_leader = None
    if election_report_path.is_file() and election_code == 0:
        election = json.loads(election_report_path.read_text(encoding="utf-8")).get("lan_election") or {}
        election_leader = (election.get("leader") or {}).get("node_name")

    hub_nodes = [node for node in nodes if node.name in {"pegasus", "atlas"}]
    if len(hub_nodes) < 2:
        checks.append(
            {
                "name": "hub_nodes_configured",
                "status": "skipped",
                "detail": "styx.yaml has no pegasus/atlas hub; use styx.yaml.runners",
            }
        )
        print("SKIP: no pegasus/atlas in styx.yaml")
    else:
        entrypoint = site_entrypoint_for(hub_nodes[0], nodes, election_leader=election_leader)
        if entrypoint is None:
            entrypoint = by_name.get("pegasus") or hub_nodes[0]

        # SSH to elected site entrypoint (port 22 before Styx gateway install).
        connection = _node_ssh_connection(
            entrypoint,
            nodes,
            config.get("cluster", {}).get("ssh_user") if isinstance(config.get("cluster"), dict) else None,
            config,
            inventory=inventory,
            local_node=local_node,
            election_leader=election_leader,
            gateway_ssh_port=ssh_port,
        )
        ok, detail = _run_ssh_command(
            connection.target,
            "echo styx-cross-site-ok",
            port=connection.port,
            jump=connection.jump,
            timeout=30.0,
        )
        name = f"ssh_entrypoint_{entrypoint.name}"
        if ok and "styx-cross-site-ok" in detail:
            checks.append({"name": name, "status": "passed", "detail": f"via {connection.target}"})
            print(f"OK    {name}: {connection.target} jump={connection.jump}")
        else:
            checks.append({"name": name, "status": "failed", "detail": detail})
            print(f"FAIL  {name}: {detail}", file=sys.stderr)

        # SSH to non-leader hub node (ProxyJump via WAN when styx gateway SSH is up).
        follower = by_name.get("atlas") if entrypoint.name == "pegasus" else by_name.get("pegasus")
        if follower is not None:
            follower_conn = _node_ssh_connection(
                follower,
                nodes,
                config.get("cluster", {}).get("ssh_user") if isinstance(config.get("cluster"), dict) else None,
                config,
                inventory=inventory,
                local_node=local_node,
                election_leader=election_leader or entrypoint.name,
                gateway_ssh_port=ssh_port,
            )
            ok, detail = _run_ssh_command(
                follower_conn.target,
                "echo styx-cross-site-follower-ok",
                port=follower_conn.port,
                jump=follower_conn.jump,
                timeout=30.0,
            )
            fname = f"ssh_follower_{follower.name}"
            if ok and "styx-cross-site-follower-ok" in detail:
                checks.append(
                    {
                        "name": fname,
                        "status": "passed",
                        "detail": f"target={follower_conn.target} jump={follower_conn.jump}",
                    }
                )
                print(f"OK    {fname}: jump={follower_conn.jump}")
            else:
                checks.append({"name": fname, "status": "failed", "detail": detail})
                print(f"FAIL  {fname}: {detail}", file=sys.stderr)

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "runner": runner_name,
        "checks": checks,
        "failed": sum(1 for item in checks if item["status"] == "failed"),
    }
    REPORT_PATH.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    if summary["failed"]:
        return 1
    if not checks:
        print("No cross-site checks ran (configure pegasus/atlas/thor in styx.yaml)")
        return 0
    print("Cross-site connectivity checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
