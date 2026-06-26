"""Automatic LAN and public IP detection for Styx nodes."""

from __future__ import annotations

import ipaddress
import shutil
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from .inventory import SystemInventory, safe_run
from .lan_election import local_lan_subnet, parse_interface_ipv4

_PRIVATE_IPV4_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def is_private_ipv4(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    return any(ip in network for network in _PRIVATE_IPV4_NETWORKS)


def detect_lan_ipv4(inventory: SystemInventory) -> str | None:
    """Return the local LAN IPv4 address used for co-located cluster routing."""
    for candidate in (inventory.bootstrap_ipv4, inventory.primary_lan_ip):
        if candidate and is_private_ipv4(candidate):
            return candidate.split("%", 1)[0]

    for address, _network in parse_interface_ipv4(inventory.network_interfaces):
        if is_private_ipv4(address):
            return address
    return None


def detect_public_ipv4() -> str | None:
    """Detect the router WAN / public IPv4 address."""
    result = safe_run("detect_public_ipv4", ["curl", "-4", "-fsS", "https://ifconfig.me"], timeout=8.0)
    if result.returncode == 0 and result.stdout.strip():
        candidate = result.stdout.strip().split()[0]
        if "." in candidate:
            return candidate
    return None


def detect_public_ipv6() -> str | None:
    """Detect the router WAN / public IPv6 address when available."""
    result = safe_run("detect_public_ipv6", ["curl", "-6", "-fsS", "https://ifconfig.me"], timeout=8.0)
    if result.returncode == 0 and result.stdout.strip():
        candidate = result.stdout.strip().split()[0]
        if ":" in candidate:
            return candidate.split("%", 1)[0]
    return None


def resolve_dns_ipv4(hostname: str) -> str | None:
    """Resolve a hostname (e.g. node.duckdns.org) to its public A record."""
    try:
        infos = socket.getaddrinfo(hostname, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except OSError:
        return None
    for info in infos:
        candidate = info[4][0]
        if "." in candidate and not is_private_ipv4(candidate):
            return candidate
    return None


def resolve_dns_ipv6(hostname: str) -> str | None:
    """Resolve a hostname (e.g. node.duckdns.org) to its AAAA record."""
    try:
        infos = socket.getaddrinfo(hostname, None, family=socket.AF_INET6, type=socket.SOCK_STREAM)
    except OSError:
        return None
    for info in infos:
        candidate = info[4][0]
        if ":" in candidate:
            return candidate.split("%", 1)[0]
    return None


def _tcp_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _nmap_scan(subnet: str, port: int) -> list[str]:
    """Return IPs with port open using nmap (fast path)."""
    result = safe_run(
        "nmap_scan",
        ["nmap", "-p", str(port), "--open", "-oG", "-", subnet],
        timeout=30.0,
    )
    hits: list[str] = []
    for line in result.stdout.splitlines():
        if "Ports:" not in line or "open" not in line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            hits.append(parts[1])
    return hits


def _socket_scan(subnet: ipaddress.IPv4Network, port: int, *, workers: int = 64) -> list[str]:
    """Return IPs with port open using parallel TCP connects (nmap fallback)."""
    hosts = [str(h) for h in subnet.hosts()]
    hits: list[str] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_tcp_port_open, h, port): h for h in hosts}
        for future in as_completed(futures):
            if future.result():
                hits.append(futures[future])
    return hits


def scan_lan_for_styx_peers(inventory: SystemInventory, port: int = 47810) -> list[str]:
    """Return LAN IPs that have the Styx gateway port open.

    Uses nmap when available for speed; falls back to parallel socket scan.
    Excludes the local machine's own IP.
    """
    subnet = local_lan_subnet(inventory)
    if subnet is None:
        return []

    own_ip = inventory.primary_lan_ip or inventory.bootstrap_ipv4

    if shutil.which("nmap"):
        candidates = _nmap_scan(str(subnet), port)
    else:
        candidates = _socket_scan(subnet, port)

    return [ip for ip in candidates if ip != own_ip]
