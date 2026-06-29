"""Built-in Styx backbone and site-scoped network plan."""

from __future__ import annotations

import ipaddress
from typing import Any

# Fixed CIDR layout for Styx gateway clusters. Operators do not edit these in styx.yaml.
DEFAULT_NETWORK: dict[str, str] = {
    "ipv4_supernet": "10.0.0.0/14",
    "ipv6_supernet": "fd00:cafe::/48",
    "mesh_ipv4": "10.0.0.0/16",
    "site_ipv4": "10.0.0.0/16",
    "infra_ipv4": "10.1.0.0/16",
    "pod_ipv4": "10.2.0.0/16",
    "service_ipv4": "10.3.0.0/16",
    "mesh_ipv6": "fd00:cafe:0::/48",
    "site_ipv6": "fd00:cafe:0::/48",
    "infra_ipv6": "fd00:cafe:1::/56",
    "pod_ipv6": "fd00:cafe:2::/56",
    "service_ipv6": "fd00:cafe:3::/112",
    # Roadwarrior is just the conventional mobile site index.
    "roadwarrior_ipv4": "10.0.250.0/24",
    "roadwarrior_ipv6": "fd00:cafe:0:250::/64",
    "pistyx_ipv4": "10.0.250.1/32",
    "pistyx_ipv6": "fd00:cafe:0:250::1/128",
}

MESH_IPV4_NETWORK = ipaddress.ip_network(DEFAULT_NETWORK["mesh_ipv4"], strict=False)
MESH_IPV6_NETWORK = ipaddress.ip_network(DEFAULT_NETWORK["mesh_ipv6"], strict=False)
SITE_IPV4_NETWORK = ipaddress.ip_network(DEFAULT_NETWORK["site_ipv4"], strict=False)
SITE_IPV6_NETWORK = ipaddress.ip_network(DEFAULT_NETWORK["site_ipv6"], strict=False)
ROADWARRIOR_IPV4_NETWORK = ipaddress.ip_network(DEFAULT_NETWORK["roadwarrior_ipv4"], strict=False)
ROADWARRIOR_IPV6_NETWORK = ipaddress.ip_network(DEFAULT_NETWORK["roadwarrior_ipv6"], strict=False)

ROADWARRIOR_SITE_INDEX = 250
PISTYX_HOST_SUFFIX = 1
SITE_CLIENT_OFFSET = 2
ROADWARRIOR_CLIENT_OFFSET = SITE_CLIENT_OFFSET

# Backward-compatible constants for the mobile site. Per-LAN pistyx addresses are derived with
# pistyx_ipv4_for_site() / pistyx_ipv6_for_site().
PISTYX_IPV4 = str(ipaddress.ip_interface(DEFAULT_NETWORK["pistyx_ipv4"]).ip)   # 10.0.250.1
PISTYX_IPV6 = str(ipaddress.ip_interface(DEFAULT_NETWORK["pistyx_ipv6"]).ip)   # fd00:cafe:0:250::1


def mesh_ipv4_for_node(index: int) -> str:
    """Return the backbone mesh IPv4 address for a node at the given list index."""
    host_number = index + 1
    return str(ipaddress.ip_address(int(MESH_IPV4_NETWORK.network_address) + host_number))


def mesh_ipv6_for_node(index: int) -> str:
    """Return the backbone mesh IPv6 address for a node at the given list index."""
    host_number = index + 1
    return str(ipaddress.ip_address(int(MESH_IPV6_NETWORK.network_address) + host_number))


def _validate_site_index(site_index: int) -> int:
    if not isinstance(site_index, int) or site_index < 0 or site_index > 255:
        raise ValueError("site_index must be between 0 and 255")
    return site_index


def _validate_host_suffix(host_suffix: int) -> int:
    if not isinstance(host_suffix, int) or host_suffix < 1 or host_suffix > 254:
        raise ValueError("host_suffix must be between 1 and 254")
    return host_suffix


def site_ipv4_network(site_index: int) -> str:
    """Return the /24 for a site. Site N owns 10.0.N.0/24."""
    site_index = _validate_site_index(site_index)
    return str(ipaddress.ip_network(f"10.0.{site_index}.0/24", strict=False))


def site_ipv6_network(site_index: int) -> str:
    """Return the /64 for a site. Site N owns fd00:cafe:0:N::/64."""
    site_index = _validate_site_index(site_index)
    return str(ipaddress.ip_network(f"fd00:cafe:0:{site_index:x}::/64", strict=False))


def site_ipv4_for_host(site_index: int, host_suffix: int) -> str:
    """Return a site-scoped IPv4 identity.

    The site index is the third octet and the host suffix is the stable device identity:
    10.0.1.7 and 10.0.2.7 refer to the same logical device in different site scopes.
    """
    site_index = _validate_site_index(site_index)
    host_suffix = _validate_host_suffix(host_suffix)
    return f"10.0.{site_index}.{host_suffix}"


def site_ipv6_for_host(site_index: int, host_suffix: int) -> str:
    """Return the IPv6 twin for a site-scoped device identity."""
    site_index = _validate_site_index(site_index)
    host_suffix = _validate_host_suffix(host_suffix)
    return f"fd00:cafe:0:{site_index:x}::{host_suffix:x}"


def pistyx_ipv4_for_site(site_index: int) -> str:
    """Return the pistyx gateway identity in a site's address scope."""
    return site_ipv4_for_host(site_index, PISTYX_HOST_SUFFIX)


def pistyx_ipv6_for_site(site_index: int) -> str:
    """Return the pistyx gateway IPv6 identity in a site's address scope."""
    return site_ipv6_for_host(site_index, PISTYX_HOST_SUFFIX)


def client_ipv4_for_site(index: int, *, site_index: int) -> str:
    """Return a client IPv4 in a site scope, preserving suffix across sites."""
    return site_ipv4_for_host(site_index, SITE_CLIENT_OFFSET + index)


def client_ipv6_for_site(index: int, *, site_index: int) -> str:
    """Return a client IPv6 in a site scope, preserving suffix across sites."""
    return site_ipv6_for_host(site_index, SITE_CLIENT_OFFSET + index)


def client_site_suffix(slot: int, *, node_count: int) -> int:
    """Host-suffix for client `slot` in a site, ABOVE the reserved pi band.

    Every pi reserves its host-suffix in every site (pistyx/init = .1, the next pi = .2, ...), so
    a client must never land on a pi's reserved identity. With N nodes, client slots map to the
    first free suffixes at/above SITE_CLIENT_OFFSET that aren't the gateway (.1) or a node suffix.
    """
    reserved = {PISTYX_HOST_SUFFIX} | {i + 1 for i in range(max(node_count, 0))}
    suffix = SITE_CLIENT_OFFSET
    remaining = slot
    while suffix <= 254:
        if suffix not in reserved:
            if remaining <= 0:
                return suffix
            remaining -= 1
        suffix += 1
    raise ValueError("no free client host-suffix available in the site")


def cluster_stack_mode(config: dict[str, Any]) -> str:
    cluster = config.get("cluster")
    if not isinstance(cluster, dict):
        return "dual-stack"
    mode = cluster.get("mode", "dual-stack")
    return mode if isinstance(mode, str) else "dual-stack"


def assign_node_mesh_ips(config: dict[str, Any]) -> None:
    """Fill missing per-node backbone mesh IPs from the built-in plan."""
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


def roadwarrior_ipv4_for_index(index: int, *, site_index: int = ROADWARRIOR_SITE_INDEX) -> str:
    """Client IPv4 for a slot in a site scope; defaults to the mobile roadwarrior site."""
    return client_ipv4_for_site(index, site_index=site_index)


def roadwarrior_ipv6_for_index(index: int, *, site_index: int = ROADWARRIOR_SITE_INDEX) -> str:
    """Client IPv6 for a slot in a site scope; defaults to the mobile roadwarrior site."""
    return client_ipv6_for_site(index, site_index=site_index)


def allocate_roadwarrior_ips(
    issued_v4: set[str] | None = None,
    issued_v6: set[str] | None = None,
    *,
    stack_mode: str = "dual-stack",
    site_index: int = ROADWARRIOR_SITE_INDEX,
) -> tuple[str | None, str | None]:
    """Next free client IPs within a site scope."""
    issued_v4 = issued_v4 or set()
    issued_v6 = issued_v6 or set()
    want_v4 = stack_mode in {"dual-stack", "ipv4-only"}
    want_v6 = stack_mode in {"dual-stack", "ipv6-only"}
    site_index = _validate_site_index(site_index)

    ipv4 = None
    if want_v4:
        for index in range(253):
            candidate = roadwarrior_ipv4_for_index(index, site_index=site_index)
            if candidate != pistyx_ipv4_for_site(site_index) and candidate not in issued_v4:
                ipv4 = candidate
                break

    ipv6 = None
    if want_v6:
        for index in range(253):
            candidate = roadwarrior_ipv6_for_index(index, site_index=site_index)
            if candidate != pistyx_ipv6_for_site(site_index) and candidate not in issued_v6:
                ipv6 = candidate
                break

    return ipv4, ipv6
