"""Built-in Styx backbone network plan (not user-configurable in MVP2)."""

from __future__ import annotations

import ipaddress
from typing import Any

# Fixed CIDR layout for Styx gateway clusters. Operators do not edit these in styx.yaml.
DEFAULT_NETWORK: dict[str, str] = {
    "ipv4_supernet": "10.0.0.0/14",
    "ipv6_supernet": "fd00:cafe::/48",
    "mesh_ipv4": "10.0.0.0/16",
    "infra_ipv4": "10.1.0.0/16",
    "pod_ipv4": "10.2.0.0/16",
    "service_ipv4": "10.3.0.0/16",
    "mesh_ipv6": "fd00:cafe:0::/48",
    "infra_ipv6": "fd00:cafe:1::/56",
    "pod_ipv6": "fd00:cafe:2::/56",
    "service_ipv6": "fd00:cafe:3::/112",
    "roadwarrior_ipv4": "10.0.250.0/24",
    "roadwarrior_ipv6": "fd00:cafe:0:250::/64",
}

MESH_IPV4_NETWORK = ipaddress.ip_network(DEFAULT_NETWORK["mesh_ipv4"], strict=False)
MESH_IPV6_NETWORK = ipaddress.ip_network(DEFAULT_NETWORK["mesh_ipv6"], strict=False)


def mesh_ipv4_for_node(index: int) -> str:
    """Return the mesh IPv4 address for a node at the given list index."""
    host_number = index + 1
    return str(ipaddress.ip_address(int(MESH_IPV4_NETWORK.network_address) + host_number))


def mesh_ipv6_for_node(index: int) -> str:
    """Return the mesh IPv6 address for a node at the given list index."""
    host_number = index + 1
    return str(ipaddress.ip_address(int(MESH_IPV6_NETWORK.network_address) + host_number))


def cluster_stack_mode(config: dict[str, Any]) -> str:
    cluster = config.get("cluster")
    if not isinstance(cluster, dict):
        return "dual-stack"
    mode = cluster.get("mode", "dual-stack")
    return mode if isinstance(mode, str) else "dual-stack"


def assign_node_mesh_ips(config: dict[str, Any]) -> None:
    """Fill missing per-node mesh IPs from the built-in plan."""
    nodes = config.get("nodes")
    if not isinstance(nodes, list):
        return

    mode = cluster_stack_mode(config)
    assign_ipv4 = mode in {"dual-stack", "ipv4-only"}
    assign_ipv6 = mode in {"dual-stack", "ipv6-only"}

    for index, item in enumerate(nodes):
        if not isinstance(item, dict):
            continue
        if assign_ipv4 and not item.get("ipv4"):
            item["ipv4"] = mesh_ipv4_for_node(index)
        if assign_ipv6 and not item.get("ipv6"):
            item["ipv6"] = mesh_ipv6_for_node(index)
