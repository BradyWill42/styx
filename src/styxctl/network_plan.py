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
    # Reserved stable overlay address for the movable pistyx egress identity. Carved from the
    # roadwarrior range (.1) so it sits OUTSIDE the index-based mesh allocator and never collides.
    "pistyx_ipv4": "10.0.250.1/32",
    "pistyx_ipv6": "fd00:cafe:0:250::1/128",
}

MESH_IPV4_NETWORK = ipaddress.ip_network(DEFAULT_NETWORK["mesh_ipv4"], strict=False)
MESH_IPV6_NETWORK = ipaddress.ip_network(DEFAULT_NETWORK["mesh_ipv6"], strict=False)
ROADWARRIOR_IPV4_NETWORK = ipaddress.ip_network(DEFAULT_NETWORK["roadwarrior_ipv4"], strict=False)
ROADWARRIOR_IPV6_NETWORK = ipaddress.ip_network(DEFAULT_NETWORK["roadwarrior_ipv6"], strict=False)
PISTYX_IPV4 = str(ipaddress.ip_interface(DEFAULT_NETWORK["pistyx_ipv4"]).ip)   # 10.0.250.1
PISTYX_IPV6 = str(ipaddress.ip_interface(DEFAULT_NETWORK["pistyx_ipv6"]).ip)   # fd00:cafe:0:250::1


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


def roadwarrior_ipv4_for_index(index: int) -> str:
    """Roadwarrior IPv4 for the given client slot. Offset +2 keeps .0 (network) and .1 (pistyx) reserved."""
    return str(ipaddress.ip_address(int(ROADWARRIOR_IPV4_NETWORK.network_address) + index + 2))


def roadwarrior_ipv6_for_index(index: int) -> str:
    """Roadwarrior IPv6 for the given client slot (same +2 offset as the v4 pool)."""
    return str(ipaddress.ip_address(int(ROADWARRIOR_IPV6_NETWORK.network_address) + index + 2))


def allocate_roadwarrior_ips(
    issued_v4: set[str] | None = None,
    issued_v6: set[str] | None = None,
    *,
    stack_mode: str = "dual-stack",
) -> tuple[str | None, str | None]:
    """Next free roadwarrior IPs (skipping .0/.255, the reserved pistyx address, and any already issued)."""
    issued_v4 = issued_v4 or set()
    issued_v6 = issued_v6 or set()
    want_v4 = stack_mode in {"dual-stack", "ipv4-only"}
    want_v6 = stack_mode in {"dual-stack", "ipv6-only"}

    ipv4 = None
    if want_v4:
        for index in range(ROADWARRIOR_IPV4_NETWORK.num_addresses):
            candidate = roadwarrior_ipv4_for_index(index)
            addr = ipaddress.ip_address(candidate)
            if addr not in ROADWARRIOR_IPV4_NETWORK or addr == ROADWARRIOR_IPV4_NETWORK.broadcast_address:
                break
            if candidate != PISTYX_IPV4 and candidate not in issued_v4:
                ipv4 = candidate
                break

    ipv6 = None
    if want_v6:
        for index in range(4096):  # bounded scan of the /64 pool
            candidate = roadwarrior_ipv6_for_index(index)
            if candidate != PISTYX_IPV6 and candidate not in issued_v6:
                ipv6 = candidate
                break

    return ipv4, ipv6
