#!/usr/bin/env python3
"""Stage 2: real SSH connectivity between self-hosted runners (gateway port 47810)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runner_lib import (
    REPO_ROOT,
    fail_check,
    pass_check,
    exit_from_checks,
    prepare_styx_yaml,
    runner_name,
)


def main() -> int:
    name = runner_name()
    print(f"=== Stage 2 — connectivity: {name} ===")
    prepare_styx_yaml(REPO_ROOT)

    from styxctl.bootstrap_config import load_operational_config
    from styxctl.gateway import parse_gateway_ports
    from styxctl.inventory import collect_inventory
    from styxctl.k3s_cluster import _node_ssh_connection, _run_ssh_command
    from styxctl.nodes import identify_local_node, parse_nodes

    inventory = collect_inventory()
    config = load_operational_config(REPO_ROOT / "styx.yaml", inventory=inventory)
    nodes = parse_nodes(config)
    local_node = identify_local_node(nodes, inventory, config)
    gateway = parse_gateway_ports(config)
    by_name = {node.name: node for node in nodes}

    if local_node is None:
        fail_check(checks, "local_node", f"host {inventory.hostname!r} not in styx.yaml")
        return exit_from_checks(name, "connectivity", checks)

    for peer in nodes:
        if peer.name == local_node.name:
            continue

        connection = _node_ssh_connection(
            peer,
            nodes,
            None,
            config,
            inventory=inventory,
            local_node=local_node,
            gateway_ssh_port=gateway.ssh,
        )
        ok, detail = _run_ssh_command(
            connection.target,
            "echo styx-connectivity-ok",
            port=connection.port,
            jump=connection.jump,
            timeout=30.0,
        )
        check_name = f"ssh_{peer.name}"
        label = f"port={connection.port} target={connection.target}"
        if connection.jump:
            label += f" jump={connection.jump}"
        if ok and "styx-connectivity-ok" in detail:
            pass_check(checks, check_name, label)
        else:
            fail_check(checks, check_name, detail or label)

    return exit_from_checks(name, "connectivity", checks)


if __name__ == "__main__":
    raise SystemExit(main())
