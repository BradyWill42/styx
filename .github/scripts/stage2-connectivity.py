#!/usr/bin/env python3
"""Stage 2: SSH interconnectivity between runners on Styx gateway port 47810."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runner_lib import (
    REPO_ROOT,
    fail_check,
    pass_check,
    skip_check,
    exit_from_checks,
    load_operational_config_with_retries,
    map_lan_ips_by_identity,
    port_listening,
    prepare_styx_yaml,
    run_ssh_probe,
    runner_name,
)



def main() -> int:
    name = runner_name()
    print(f"=== Stage 2 - connectivity: {name} ===")
    config_path = prepare_styx_yaml(REPO_ROOT)
    checks: list[dict[str, object]] = []

    from styxctl.config import config_status, validate_config
    from styxctl.gateway import parse_gateway_ports
    from styxctl.inventory import collect_inventory
    from styxctl.k3s_cluster import _node_ssh_connection
    from styxctl.network_detect import scan_lan_for_styx_peers
    from styxctl.nodes import identify_local_node, is_colocated, parse_nodes

    inventory = collect_inventory()
    config = load_operational_config_with_retries(config_path, inventory=inventory)
    nodes = parse_nodes(config)
    local_node = identify_local_node(nodes, inventory, config)
    if local_node is None:
        local_node = next((node for node in nodes if node.name == name), None)
    gateway = parse_gateway_ports(config)

    # Scan the LAN for peers with the gateway port open when nodes share a public IP.
    scanned_lan_ips: list[str] = []
    if any(is_colocated(node, nodes) for node in nodes):
        print(f"Scanning LAN for peers on port {gateway.ssh}...")
        scanned_lan_ips = scan_lan_for_styx_peers(inventory, port=gateway.ssh)
        if scanned_lan_ips:
            print(f"Found LAN peers: {', '.join(scanned_lan_ips)}")
        else:
            print("No LAN peers found via scan.")

    if local_node is None:
        fail_check(checks, "local_node", f"runner {name!r} not in styx.yaml")
        return exit_from_checks(name, "connectivity", checks)

    pass_check(checks, "local_node", local_node.name)

    # The LAN scan returns IPs but not which IP is which node — positional assignment
    # mismatches colocated peers. Map them by hostname over SSH; for colocated peers this
    # map is authoritative (correct IP if found, else None = that node ran no stage-1 leg
    # this round, so it's not on the LAN and its connectivity check is skipped).
    lan_by_name: dict[str, str] = {}
    if scanned_lan_ips:
        lan_by_name = map_lan_ips_by_identity(nodes, local_node, scanned_lan_ips, port=gateway.ssh)
        if lan_by_name:
            print("LAN identity map: " + ", ".join(f"{k}={v}" for k, v in sorted(lan_by_name.items())))
    for node in nodes:
        if node.name == local_node.name:
            continue
        if local_node.public_ipv4 and node.public_ipv4 == local_node.public_ipv4:
            node.lan_ip = lan_by_name.get(node.name)

    for node in nodes:
        label = node.public_ipv4 or "missing"
        lan = f" lan={node.lan_ip}" if node.lan_ip else ""
        if node.public_ipv4:
            pass_check(checks, f"node_{node.name}_public_ipv4", f"{label}{lan}")
        else:
            fail_check(
                checks,
                f"node_{node.name}_public_ipv4",
                f"not discovered via gateway SSH port {gateway.ssh}",
            )

    issues = validate_config(config, inventory=inventory)
    status = config_status(issues)
    if status == "INVALID":
        errors = [f"{issue.path}: {issue.message}" for issue in issues if issue.level == "error"]
        fail_check(checks, "config_validate", "; ".join(errors[:5]) or status)
    else:
        pass_check(checks, "config_validate", status)

    if port_listening(gateway.ssh):
        pass_check(checks, "gateway_listen_local", f"port {gateway.ssh}")
    else:
        fail_check(
            checks,
            "gateway_listen_local",
            f"port {gateway.ssh} not listening - run stage 1 first",
        )

    for peer in nodes:
        if peer.name == local_node.name:
            continue

        if not peer.public_ipv4:
            continue

        colocated = bool(local_node.public_ipv4 and peer.public_ipv4 == local_node.public_ipv4)
        if colocated and not peer.lan_ip:
            skip_check(
                checks,
                f"ssh_{peer.name}",
                "colocated peer not on the LAN this run (no stage-1 leg) - skipped",
            )
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
