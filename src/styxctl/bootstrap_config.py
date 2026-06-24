"""Bootstrap-time config enrichment: auto-detect IPs before DuckDNS."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from .bootstrap_mode import bootstrap_mode, dns_publish_enabled
from .inventory import SystemInventory, collect_inventory
from .network_detect import (
    REMOTE_PUBLIC_IPV4_SHELL,
    REMOTE_PUBLIC_IPV6_SHELL,
    detect_lan_ipv4,
    detect_public_ipv4,
    detect_public_ipv6,
)
from .network_plan import assign_node_mesh_ips
from .nodes import identify_local_node, parse_nodes, sites_by_public_ip

BOOTSTRAP_SSH_PORT = 22
DEFAULT_GATEWAY_SSH_PORT = 47810
_LAN_IP_COMMAND = (
    "ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f1"
)


def effective_ssh_port(config: dict[str, Any], gateway_ssh_port: int = DEFAULT_GATEWAY_SSH_PORT) -> int:
    """SSH port for cluster operations: 22 before Styx gateway install, else gateway port."""
    if bootstrap_mode(config):
        return BOOTSTRAP_SSH_PORT
    return gateway_ssh_port


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


def _ssh_user(config: dict[str, Any]) -> str:
    cluster = config.get("cluster")
    if isinstance(cluster, dict):
        user = cluster.get("ssh_user")
        if isinstance(user, str) and user.strip():
            return user.strip()
    return "ubuntu"


def _discover_remote_value(node_name: str, ssh_user: str, remote_command: str) -> str | None:
    from .k3s_cluster import _run_ssh_command

    target = f"{ssh_user}@{node_name}"
    ok, detail = _run_ssh_command(
        target,
        remote_command,
        port=BOOTSTRAP_SSH_PORT,
        timeout=20.0,
    )
    if not ok:
        return None
    candidate = detail.strip().splitlines()[-1].strip().split()[0]
    return candidate or None


def discover_remote_public_ipv4(node_name: str, ssh_user: str) -> str | None:
    value = _discover_remote_value(node_name, ssh_user, REMOTE_PUBLIC_IPV4_SHELL)
    if value and "." in value:
        return value
    return None


def discover_remote_public_ipv6(node_name: str, ssh_user: str) -> str | None:
    value = _discover_remote_value(node_name, ssh_user, REMOTE_PUBLIC_IPV6_SHELL)
    if value and ":" in value:
        return value.split("%", 1)[0]
    return None


def discover_remote_lan_ipv4(node_name: str, ssh_user: str) -> str | None:
    value = _discover_remote_value(node_name, ssh_user, _LAN_IP_COMMAND)
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

    nodes_raw = enriched.get("nodes")
    if not isinstance(nodes_raw, list):
        return enriched

    ssh_user = _ssh_user(enriched)
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
        for item in nodes_raw:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            if local_node is not None and name == local_node.name:
                continue
            if not item.get("public_ipv4"):
                discovered = discover_remote_public_ipv4(name, ssh_user)
                if discovered:
                    item["public_ipv4"] = discovered
            if not item.get("public_ipv6"):
                discovered_v6 = discover_remote_public_ipv6(name, ssh_user)
                if discovered_v6:
                    item["public_ipv6"] = discovered_v6

        parsed = parse_nodes(enriched)
        local_node = identify_local_node(parsed, inventory, enriched)
        if local_node is not None and local_node.public_ipv4:
            site_nodes = sites_by_public_ip(parsed).get(local_node.public_ipv4, [])
            local_lan = detect_lan_ipv4(inventory)
            for node in site_nodes:
                if node.name == local_node.name:
                    continue
                for item in nodes_raw:
                    if not isinstance(item, dict) or item.get("name") != node.name:
                        continue
                    if not item.get("lan_ip"):
                        lan = discover_remote_lan_ipv4(node.name, ssh_user)
                        if lan:
                            item["lan_ip"] = lan
                    break

    return enriched


def minimal_runners_config() -> dict[str, Any]:
    """Default three-runner topology; mesh IPs assigned automatically."""
    return {
        "cluster": {
            "name": "styx",
            "leader": "lan-elected",
            "ssh_user": "ubuntu",
            "bootstrap": True,
        },
        "nodes": [
            {"name": "pegasus", "role": "init-server"},
            {"name": "atlas", "role": "agent"},
            {"name": "thor", "role": "server"},
        ],
    }
