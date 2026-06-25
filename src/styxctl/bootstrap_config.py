"""Bootstrap-time config enrichment: auto-detect IPs (external DNS deferred to MVP3)."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from .bootstrap_mode import bootstrap_mode
from .gateway import parse_gateway_ports
from .inventory import SystemInventory, collect_inventory
from .network_detect import (
    REMOTE_PUBLIC_IPV4_SHELL,
    REMOTE_PUBLIC_IPV6_SHELL,
    detect_lan_ipv4,
    detect_public_ipv4,
    detect_public_ipv6,
    scan_lan_for_styx_peers,
)
from .network_plan import assign_node_mesh_ips
from .nodes import identify_local_node, parse_nodes, sites_by_public_ip

_LAN_IP_COMMAND = (
    "ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f1"
)


def load_operational_config(
    path: str | Path | None = None,
    *,
    inventory: SystemInventory | None = None,
) -> dict[str, Any]:
    """Load styx.yaml and auto-fill bootstrap fields from the local host and SSH peers."""
    from .config import find_config, load_config, resolve_config

    inventory = inventory or collect_inventory()
    candidate = Path(path) if path is not None else find_config()
    raw = load_config(candidate)
    return enrich_operational_config(resolve_config(raw), inventory)


def _discover_remote_value(
    node_name: str,
    remote_command: str,
    *,
    gateway_ssh_port: int,
) -> str | None:
    from .k3s_cluster import _run_ssh_command

    target = f"{node_name}@{node_name}"
    ok, detail = _run_ssh_command(
        target,
        remote_command,
        port=gateway_ssh_port,
        timeout=20.0,
    )
    if not ok:
        return None
    candidate = detail.strip().splitlines()[-1].strip().split()[0]
    return candidate or None


def discover_remote_public_ipv4(node_name: str, *, gateway_ssh_port: int) -> str | None:
    value = _discover_remote_value(
        node_name,
        REMOTE_PUBLIC_IPV4_SHELL,
        gateway_ssh_port=gateway_ssh_port,
    )
    if value and "." in value:
        return value
    return None


def discover_remote_public_ipv6(node_name: str, *, gateway_ssh_port: int) -> str | None:
    value = _discover_remote_value(
        node_name,
        REMOTE_PUBLIC_IPV6_SHELL,
        gateway_ssh_port=gateway_ssh_port,
    )
    if value and ":" in value:
        return value.split("%", 1)[0]
    return None


def discover_remote_lan_ipv4(node_name: str, *, gateway_ssh_port: int) -> str | None:
    value = _discover_remote_value(
        node_name,
        _LAN_IP_COMMAND,
        gateway_ssh_port=gateway_ssh_port,
    )
    if value and not value.startswith("127."):
        return value
    return None


def enrich_operational_config(
    config: dict[str, Any],
    inventory: SystemInventory,
) -> dict[str, Any]:
    """Fill missing bootstrap fields from the local host and SSH to peer nodes."""
    enriched = copy.deepcopy(config)
    assign_node_mesh_ips(enriched)
    gateway = parse_gateway_ports(enriched)

    nodes_raw = enriched.get("nodes")
    if not isinstance(nodes_raw, list):
        return enriched

    parsed = parse_nodes(enriched)
    local_node = identify_local_node(parsed, inventory, enriched)

    if local_node is not None:
        for item in nodes_raw:
            if not isinstance(item, dict) or item.get("name") != local_node.name:
                continue
            if not item.get("public_ipv4"):
                detected = detect_public_ipv4()
                if detected:
                    item["public_ipv4"] = detected
            if not item.get("public_ipv6"):
                detected_v6 = detect_public_ipv6()
                if detected_v6:
                    item["public_ipv6"] = detected_v6
            if not item.get("lan_ip"):
                lan = detect_lan_ipv4(inventory)
                if lan:
                    item["lan_ip"] = lan

    if bootstrap_mode(enriched):
        # Peers reachable on the LAN share the same public IP as the local node —
        # detect them by scanning for the gateway port rather than requiring SSH.
        local_public_ipv4 = local_node.public_ipv4 if local_node else None
        lan_peers: set[str] = set()
        if local_public_ipv4:
            lan_peers = set(scan_lan_for_styx_peers(inventory, port=gateway.ssh))

        for item in nodes_raw:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            if local_node is not None and name == local_node.name:
                continue
            if not item.get("public_ipv4"):
                if local_public_ipv4 and lan_peers:
                    # Colocated peer — same public IP, no SSH needed.
                    item["public_ipv4"] = local_public_ipv4
                else:
                    discovered = discover_remote_public_ipv4(name, gateway_ssh_port=gateway.ssh)
                    if discovered:
                        item["public_ipv4"] = discovered
            if not item.get("public_ipv6"):
                discovered_v6 = discover_remote_public_ipv6(name, gateway_ssh_port=gateway.ssh)
                if discovered_v6:
                    item["public_ipv6"] = discovered_v6

        parsed = parse_nodes(enriched)
        local_node = identify_local_node(parsed, inventory, enriched)
        if local_node is not None and local_node.public_ipv4:
            site_nodes = sites_by_public_ip(parsed).get(local_node.public_ipv4, [])
            for node in site_nodes:
                if node.name == local_node.name:
                    continue
                for item in nodes_raw:
                    if not isinstance(item, dict) or item.get("name") != node.name:
                        continue
                    if not item.get("lan_ip"):
                        lan = discover_remote_lan_ipv4(node.name, gateway_ssh_port=gateway.ssh)
                        if lan:
                            item["lan_ip"] = lan
                    break

    return enriched
