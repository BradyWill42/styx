#!/usr/bin/env python3
"""MVP3: live cross-site WireGuard IP and DNS connectivity checks."""

from __future__ import annotations

import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runner_lib import (  # noqa: E402
    REPO_ROOT,
    exit_from_checks,
    fail_check,
    pass_check,
    prepare_styx_yaml,
    run,
    runner_name,
    skip_check,
)


def _run_ip(args: list[str], *, timeout: float = 10.0) -> tuple[bool, str]:
    code, output = run(["ip", *args], timeout=timeout)
    return code == 0, output


def _ping_v4(target: str) -> tuple[bool, str]:
    code, output = run(["ping", "-4", "-c", "2", "-W", "2", target], timeout=12.0)
    if code == 0:
        summary = next((line for line in output.splitlines() if "packets transmitted" in line), "")
        rtt = next((line for line in output.splitlines() if line.startswith("rtt ") or line.startswith("round-trip ")), "")
        return True, "; ".join(part for part in (summary.strip(), rtt.strip()) if part) or target
    return False, output[-500:] if output else f"ping {target} failed"


def _system_a_records(hostname: str) -> list[str]:
    records: list[str] = []
    try:
        infos = socket.getaddrinfo(hostname, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except OSError:
        return records
    for info in infos:
        ip = info[4][0]
        if ip not in records:
            records.append(ip)
    return records


def _encode_dns_name(hostname: str) -> bytes:
    parts = hostname.rstrip(".").split(".")
    encoded = b""
    for part in parts:
        label = part.encode("idna")
        if not label or len(label) > 63:
            raise ValueError(f"invalid DNS label in {hostname!r}")
        encoded += bytes([len(label)]) + label
    return encoded + b"\0"


def _skip_dns_name(packet: bytes, offset: int) -> int:
    while True:
        if offset >= len(packet):
            raise ValueError("DNS packet ended inside a name")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("DNS packet ended inside a compressed name")
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length


def _query_local_resolver_a(hostname: str, *, timeout: float = 3.0) -> tuple[bool, list[str] | str]:
    """Ask the node-local resolver directly over UDP and return A records."""
    txid = int(time.time() * 1000) & 0xFFFF
    packet = (
        struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        + _encode_dns_name(hostname)
        + struct.pack("!HH", 1, 1)
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, ("127.0.0.1", 53))
            response, _addr = sock.recvfrom(4096)
    except OSError as exc:
        return False, str(exc)

    try:
        if len(response) < 12:
            raise ValueError("short DNS response")
        got_txid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", response[:12])
        if got_txid != txid:
            raise ValueError("transaction id mismatch")
        rcode = flags & 0x000F
        if rcode != 0:
            raise ValueError(f"resolver returned rcode {rcode}")
        offset = 12
        for _ in range(qdcount):
            offset = _skip_dns_name(response, offset) + 4
        records: list[str] = []
        for _ in range(ancount):
            offset = _skip_dns_name(response, offset)
            if offset + 10 > len(response):
                raise ValueError("short DNS answer header")
            rtype, rclass, _ttl, rdlength = struct.unpack("!HHIH", response[offset : offset + 10])
            offset += 10
            rdata = response[offset : offset + rdlength]
            offset += rdlength
            if rtype == 1 and rclass == 1 and rdlength == 4:
                ip = socket.inet_ntoa(rdata)
                if ip not in records:
                    records.append(ip)
        return True, records
    except (OSError, ValueError, struct.error) as exc:
        return False, str(exc)


def _hostname_targets(config: dict) -> dict[str, str]:
    from styxctl.nodes import node_hostname, parse_nodes

    targets: dict[str, str] = {}
    for node in parse_nodes(config):
        hostname = node_hostname(node)
        if hostname:
            targets.setdefault(hostname, f"node {node.name}")

    egress = config.get("egress")
    if isinstance(egress, dict):
        hostname = egress.get("hostname")
        if isinstance(hostname, str) and hostname.strip():
            targets.setdefault(hostname.strip(), "floating pistyx")
    return targets


def main() -> int:
    name = runner_name()
    print(f"=== MVP3 connectivity: {name} ===")
    config_path = prepare_styx_yaml(REPO_ROOT)
    checks: list[dict[str, object]] = []

    from styxctl.bootstrap_config import load_operational_config
    from styxctl.inventory import collect_inventory
    from styxctl.network_plan import node_ipv4_for_site
    from styxctl.nodes import identify_local_node, parse_nodes
    from styxctl.wireguard_mesh import _site_index_for_node, _site_indexes_for_nodes

    inventory = collect_inventory()
    config = load_operational_config(config_path, inventory=inventory)
    nodes = parse_nodes(config)
    local_node = identify_local_node(nodes, inventory, config)
    if local_node is None:
        local_node = next((node for node in nodes if node.name == name), None)
    if local_node is None:
        fail_check(checks, "local_node", f"runner {name!r} not found in styx.yaml")
        return exit_from_checks(name, "mvp3-connectivity", checks)

    node_index = {node.name: index for index, node in enumerate(nodes)}
    local_site = _site_index_for_node(nodes, local_node)
    site_indexes = _site_indexes_for_nodes(nodes)
    remote_site_peers = [
        node for node in nodes
        if node.name != local_node.name and _site_index_for_node(nodes, node) != local_site
    ]

    pass_check(checks, "local_node", f"{local_node.name} site={local_site}")
    if len(site_indexes) >= 2:
        pass_check(checks, "site_count", f"{len(site_indexes)} sites: {', '.join(map(str, site_indexes))}")
    else:
        fail_check(checks, "site_count", f"cross-site test requires at least 2 sites, found {site_indexes}")

    ok, detail = _run_ip(["link", "show", "dev", "Styx"])
    if ok:
        pass_check(checks, "interface_Styx", "present")
    else:
        fail_check(checks, "interface_Styx", detail or "missing")

    local_index = node_index[local_node.name]
    for site_index in site_indexes:
        interface = f"StyxSite{site_index}"
        expected_ip = node_ipv4_for_site(local_index, site_index=site_index)
        ok, detail = _run_ip(["-4", "addr", "show", "dev", interface])
        if not ok:
            fail_check(checks, f"interface_{interface}", detail or "missing")
            continue
        if expected_ip in detail:
            pass_check(checks, f"interface_{interface}", f"{expected_ip} present")
        else:
            fail_check(checks, f"interface_{interface}", f"expected {expected_ip}; got {detail[-300:]}")

    if not remote_site_peers:
        skip_check(checks, "cross_site_peers", "no peer from a different site in this runner's config")

    for peer in remote_site_peers:
        peer_site = _site_index_for_node(nodes, peer)
        if peer.ipv4:
            ok, detail = _ping_v4(peer.ipv4)
            check = f"ping_backbone_{peer.name}"
            if ok:
                pass_check(checks, check, f"{peer.ipv4}: {detail}")
            else:
                fail_check(checks, check, f"{peer.ipv4}: {detail}")
        else:
            fail_check(checks, f"ping_backbone_{peer.name}", "peer has no Styx backbone IPv4")

        peer_index = node_index[peer.name]
        for site_index in site_indexes:
            target = node_ipv4_for_site(peer_index, site_index=site_index)
            ok, detail = _ping_v4(target)
            check = f"ping_site{site_index}_{peer.name}"
            label = f"{target} (peer site {peer_site})"
            if ok:
                pass_check(checks, check, f"{label}: {detail}")
            else:
                fail_check(checks, check, f"{label}: {detail}")

    dns_targets = _hostname_targets(config)
    if dns_targets:
        pass_check(checks, "dns_targets", ", ".join(sorted(dns_targets)))
    else:
        fail_check(checks, "dns_targets", "no node or pistyx hostnames configured")

    for hostname, label in sorted(dns_targets.items()):
        records = _system_a_records(hostname)
        if records:
            pass_check(checks, f"dns_system_{hostname}", f"{label}: {', '.join(records)}")
        else:
            fail_check(checks, f"dns_system_{hostname}", f"{label}: no A record from system resolver")

        ok, local_result = _query_local_resolver_a(hostname)
        if ok and isinstance(local_result, list) and local_result:
            pass_check(checks, f"dns_local_{hostname}", f"127.0.0.1: {', '.join(local_result)}")
        elif ok:
            fail_check(checks, f"dns_local_{hostname}", "127.0.0.1 returned no A records")
        else:
            fail_check(checks, f"dns_local_{hostname}", f"127.0.0.1 query failed: {local_result}")

    return exit_from_checks(name, "mvp3-connectivity", checks)


if __name__ == "__main__":
    raise SystemExit(main())
