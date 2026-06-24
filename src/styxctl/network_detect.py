"""Automatic LAN and public IP detection for Styx nodes."""

from __future__ import annotations

import ipaddress

from .inventory import SystemInventory, safe_run
from .lan_election import parse_interface_ipv4

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


def detect_lan_ipv6(inventory: SystemInventory) -> str | None:
    """Return a local IPv6 address suitable for LAN routing when available."""
    if inventory.bootstrap_ipv6:
        return inventory.bootstrap_ipv6.split("%", 1)[0]
    return None


def detect_public_ipv4() -> str | None:
    """Detect the router WAN / public IPv4 address."""
    for command in (
        ["curl", "-4", "-fsS", "https://ifconfig.me"],
        ["curl", "-4", "-fsS", "https://api.ipify.org"],
        ["curl", "-4", "-fsS", "https://icanhazip.com"],
    ):
        result = safe_run("detect_public_ipv4", command, timeout=8.0)
        if result.returncode == 0 and result.stdout.strip():
            candidate = result.stdout.strip().split()[0]
            if "." in candidate:
                return candidate
    return None


def detect_public_ipv6() -> str | None:
    """Detect the router WAN / public IPv6 address when available."""
    for command in (
        ["curl", "-6", "-fsS", "https://ifconfig.me"],
        ["curl", "-6", "-fsS", "https://api64.ipify.org"],
        ["curl", "-6", "-fsS", "https://icanhazip.com"],
    ):
        result = safe_run("detect_public_ipv6", command, timeout=8.0)
        if result.returncode == 0 and result.stdout.strip():
            candidate = result.stdout.strip().split()[0]
            if ":" in candidate:
                return candidate.split("%", 1)[0]
    return None


# Shell one-liners for remote discovery over SSH (bootstrap port 22).
REMOTE_PUBLIC_IPV4_SHELL = (
    "curl -4 -fsS https://ifconfig.me 2>/dev/null || "
    "curl -4 -fsS https://api.ipify.org 2>/dev/null || "
    "curl -4 -fsS https://icanhazip.com 2>/dev/null || true"
)
REMOTE_PUBLIC_IPV6_SHELL = (
    "curl -6 -fsS https://ifconfig.me 2>/dev/null || "
    "curl -6 -fsS https://api64.ipify.org 2>/dev/null || "
    "curl -6 -fsS https://icanhazip.com 2>/dev/null || true"
)
