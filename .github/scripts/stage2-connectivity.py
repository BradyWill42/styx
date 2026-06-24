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
    port_listening,
    prepare_styx_yaml,
    run_ssh_probe,
    runner_name,
)


def main() -> int:
    name = runner_name()
    print(f"=== Stage 2 — connectivity: {name} ===")
    config_path = prepare_styx_yaml(REPO_ROOT)
    checks: list[dict[str, object]] = []

    from styxctl.bootstrap_config import load_operational_config
    from styxctl.gateway import parse_gateway_ports
    from styxctl.inventory import collect_inventory
    from styxctl.k3s_cluster import _node_ssh_connection
    from styxctl.nodes import identify_local_node, parse_nodes

    inventory = collect_inventory()
    config = load_operational_config(config_path, inventory=inventory)
    nodes = parse_nodes(config)
    local_node = identify_local_node(nodes, inventory, config)
    if local_node is None:
        local_node = next((node for node in nodes if node.name == name), None)
    gateway = parse_gateway_ports(config)

    if local_node is None:
        fail_check(checks, "local_node", f"host {inventory.hostname!r} not in styx.yaml")
        return exit_from_checks(name, "connectivity", checks)

    pass_check(checks, "local_node", local_node.name)

    if not local_node.public_ipv4:
        fail_check(checks, "local_public_ipv4", "missing after bootstrap enrichment")
    else:
        pass_check(checks, "local_public_ipv4", local_node.public_ipv4)

    if port_listening(gateway.ssh):
        pass_check(checks, "gateway_listen_local", f"port {gateway.ssh}")
    else:
        fail_check(
            checks,
            "gateway_listen_local",
            f"port {gateway.ssh} not listening — run stage 1 gateway configure first",
        )

    for peer in nodes:
        if peer.name == local_node.name:
            continue

        if not peer.public_ipv4:
            fail_check(checks, f"peer_{peer.name}_public_ipv4", "missing in operational config")
            continue
        pass_check(checks, f"peer_{peer.name}_public_ipv4", peer.public_ipv4)

        connection = _node_ssh_connection(
            peer,
            nodes,
            None,
            config,
            inventory=inventory,
            local_node=local_node,
            gateway_ssh_port=gateway.ssh,
        )
        ok, detail = run_ssh_probe(
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
        if peer.lan_ip:
            label += f" lan={peer.lan_ip}"
        if ok and "styx-connectivity-ok" in detail:
            pass_check(checks, check_name, label)
        else:
            fail_check(checks, check_name, detail or label)

    return exit_from_checks(name, "connectivity", checks)


if __name__ == "__main__":
    raise SystemExit(main())
