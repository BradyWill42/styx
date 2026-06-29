"""Bootstrap-time config enrichment: auto-detect local IPs and resolve peer public IPs
via their DuckDNS hostnames (colocated peers get their lan_ip from a LAN scan)."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Callable

from .gateway import parse_gateway_ports
from .inventory import SystemInventory, collect_inventory
from .network_detect import (
    detect_lan_ipv4,
    detect_public_ipv4,
    detect_public_ipv6,
    resolve_dns_ipv4,
    resolve_dns_ipv6,
    scan_lan_for_styx_peers,
)
from .network_plan import assign_node_mesh_ips
from .nodes import (
    ClusterNode,
    identify_local_node,
    node_dns_name,
    node_ssh_user,
    parse_nodes,
    sites_by_public_ip,
)

SshRunner = Callable[[str, str], tuple[bool, str]]


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


def _map_lan_ips_by_identity(
    nodes: list[ClusterNode],
    local_node: ClusterNode | None,
    scanned_ips: list[str],
    *,
    port: int,
    runner: SshRunner | None = None,
) -> dict[str, str]:
    """Map LAN scan hits to node names by asking each candidate for `hostname -s`."""
    if not scanned_ips:
        return {}
    if runner is None:
        from .k3s_cluster import _run_ssh_command

        def runner(target: str, command: str) -> tuple[bool, str]:
            return _run_ssh_command(target, command, port=port, timeout=15.0)

    mapping: dict[str, str] = {}
    unclaimed = list(scanned_ips)
    for node in nodes:
        if local_node is not None and node.name == local_node.name:
            continue
        user = node_ssh_user(node)
        for ip in list(unclaimed):
            ok, detail = runner(f"{user}@{ip}", "hostname -s")
            if not ok or not detail.strip():
                continue
            got = detail.strip().splitlines()[-1].strip().lower()
            if got == node.name.lower():
                mapping[node.name] = ip
                unclaimed.remove(ip)
                break
    return mapping


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

    # Auto-discovery is always on: detect local IPs, resolve peers by their DuckDNS
    # hostname, and map colocated peers to a lan_ip via the LAN scan.
    # Peers reachable on the LAN share the same public IP as the local node.
    # local_node is a stale parsed dataclass — read the freshly written public IP
    # directly from nodes_raw, or fall back to detect_public_ipv4().
    local_public_ipv4 = None
    if local_node is not None:
        for item in nodes_raw:
            if isinstance(item, dict) and item.get("name") == local_node.name:
                local_public_ipv4 = item.get("public_ipv4") or detect_public_ipv4()
                break
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
        # Dynamic DNS ({name}.duckdns.org) is the authoritative cross-site
        # rendezvous: resolving it yields the peer's current WAN IP without SSH
        # or a port-forward. Colocated peers resolve to the same IP as the local
        # node, which the LAN scan then maps to a lan_ip.
        dns_name = node_dns_name(item.get("hostname"))
        if not item.get("public_ipv4"):
            resolved = resolve_dns_ipv4(dns_name) if dns_name else None
            if resolved:
                item["public_ipv4"] = resolved
            elif local_public_ipv4 and lan_peers:
                # No DNS name configured — a colocated peer shares the local WAN IP.
                item["public_ipv4"] = local_public_ipv4
        if not item.get("public_ipv6"):
            resolved_v6 = resolve_dns_ipv6(dns_name) if dns_name else None
            if resolved_v6:
                item["public_ipv6"] = resolved_v6

    parsed = parse_nodes(enriched)
    local_node = identify_local_node(parsed, inventory, enriched)
    if local_node is not None and local_node.public_ipv4:
        site_nodes = sites_by_public_ip(parsed).get(local_node.public_ipv4, [])
        # Exclude the local node's own LAN IP from candidates so we don't assign it to a peer.
        local_lan = None
        for item in nodes_raw:
            if isinstance(item, dict) and item.get("name") == local_node.name:
                local_lan = item.get("lan_ip")
                break
        # Prefer identity-mapped IPs from the LAN scan; fall back to positional assignment only
        # when identity probing is unavailable.
        peer_candidates = sorted(ip for ip in lan_peers if ip != local_lan)
        identity_lan_ips = _map_lan_ips_by_identity(site_nodes, local_node, peer_candidates, port=gateway.ssh)
        fallback_candidates = [ip for ip in peer_candidates if ip not in set(identity_lan_ips.values())]
        candidate_idx = 0
        for node in site_nodes:
            if node.name == local_node.name:
                continue
            for item in nodes_raw:
                if not isinstance(item, dict) or item.get("name") != node.name:
                    continue
                if item.get("lan_ip"):
                    break
                if node.name in identity_lan_ips:
                    item["lan_ip"] = identity_lan_ips[node.name]
                elif candidate_idx < len(fallback_candidates):
                    item["lan_ip"] = fallback_candidates[candidate_idx]
                    candidate_idx += 1
                break

    return enriched
