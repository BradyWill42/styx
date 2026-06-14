"""Styx cluster node definitions from styx.yaml."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
import socket
from typing import Any

from .inventory import SystemInventory

VALID_ROLES = frozenset({"init-server", "server", "agent"})
DEFAULT_DUCKDNS_DOMAIN = "duckdns.org"


def duckdns_domain(config: dict[str, Any]) -> str:
    dns = config.get("dns")
    if isinstance(dns, dict):
        domain = dns.get("domain")
        if isinstance(domain, str) and domain.strip():
            return domain.strip()
    return DEFAULT_DUCKDNS_DOMAIN


def resolve_hostname(hostname: str) -> str | None:
    try:
        results = socket.getaddrinfo(hostname, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except OSError:
        return None
    if not results:
        return None
    return results[0][4][0]


def node_hostname(config: dict[str, Any], node: ClusterNode) -> str | None:
    if node.hostname:
        return node.hostname

    dns = config.get("dns")
    if not isinstance(dns, dict):
        return None

    domain = duckdns_domain(config)
    fixed = dns.get("fixed_endpoints")
    if isinstance(fixed, dict):
        subdomain = fixed.get(node.name)
        if isinstance(subdomain, str) and subdomain.strip():
            return f"{subdomain.strip()}.{domain}"

    auto_endpoint = dns.get("auto_endpoint")
    if isinstance(auto_endpoint, str) and auto_endpoint.strip() and node.name == auto_endpoint.strip():
        return f"{auto_endpoint.strip()}.{domain}"

    return None


def node_subdomain(hostname: str, config: dict[str, Any]) -> str:
    domain = duckdns_domain(config)
    suffix = f".{domain}"
    if hostname.endswith(suffix):
        return hostname[: -len(suffix)]
    return hostname.split(".", 1)[0]


@dataclass(slots=True)
class ClusterNode:
    name: str
    ipv4: str | None
    ipv6: str | None
    role: str
    hostname: str | None = None
    ssh_user: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @property
    def primary_ip(self) -> str | None:
        return self.ipv4 or self.ipv6

    def connectivity_host(self, config: dict[str, Any]) -> str | None:
        return node_hostname(config, self) or self.primary_ip

    def resolved_ipv4(self, config: dict[str, Any]) -> str | None:
        host = node_hostname(config, self)
        if host:
            return resolve_hostname(host)
        return self.ipv4

    def all_ips(self) -> list[str]:
        ips: list[str] = []
        if self.ipv4:
            ips.append(self.ipv4)
        if self.ipv6:
            ips.append(self.ipv6)
        return ips


def parse_nodes(config: dict[str, Any]) -> list[ClusterNode]:
    raw_nodes = config.get("nodes")
    if raw_nodes is None:
        return []

    if not isinstance(raw_nodes, list):
        return []

    cluster = config.get("cluster", {})
    default_ssh_user = cluster.get("ssh_user") if isinstance(cluster.get("ssh_user"), str) else None

    nodes: list[ClusterNode] = []
    for index, item in enumerate(raw_nodes):
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            name = f"node-{index + 1}"
        role = item.get("role", "agent")
        if not isinstance(role, str):
            role = "agent"
        ipv4 = item.get("ipv4")
        ipv6 = item.get("ipv6")
        host = item.get("hostname")
        ssh_user = item.get("ssh_user")
        nodes.append(
            ClusterNode(
                name=name.strip(),
                ipv4=ipv4.strip() if isinstance(ipv4, str) and ipv4.strip() else None,
                ipv6=ipv6.strip() if isinstance(ipv6, str) and ipv6.strip() else None,
                role=role.strip(),
                hostname=host.strip() if isinstance(host, str) and host.strip() else None,
                ssh_user=ssh_user.strip() if isinstance(ssh_user, str) and ssh_user.strip() else default_ssh_user,
            )
        )
    return nodes


def validate_nodes(nodes: list[ClusterNode], config: dict[str, Any] | None = None) -> list[str]:
    errors: list[str] = []
    if not nodes:
        return errors

    init_servers = [node for node in nodes if node.role == "init-server"]
    if len(init_servers) != 1:
        errors.append("nodes: exactly one init-server node is required")

    seen_mesh_ips: set[str] = set()
    seen_hosts: set[str] = set()
    for node in nodes:
        if node.role not in VALID_ROLES:
            errors.append(f"nodes.{node.name}.role: expected init-server, server, or agent")

        host = node.connectivity_host(config or {}) if config else (node.hostname or node.primary_ip)
        if not host:
            errors.append(
                f"nodes.{node.name}: set hostname (DuckDNS) or ipv4/ipv6 mesh address"
            )
        elif host in seen_hosts:
            errors.append(f"nodes.{node.name}: duplicate connectivity host {host}")
        else:
            seen_hosts.add(host)

        if not node.ipv4 and not node.ipv6:
            errors.append(
                f"nodes.{node.name}: mesh ipv4 or ipv6 is required for k3s --node-ip"
            )
        for ip in node.all_ips():
            if ip in seen_mesh_ips:
                errors.append(f"nodes.{node.name}: duplicate mesh IP {ip}")
            seen_mesh_ips.add(ip)
            try:
                ipaddress.ip_address(ip.split("%", 1)[0])
            except ValueError:
                errors.append(f"nodes.{node.name}: invalid mesh IP address {ip}")
    return errors


def identify_local_node(nodes: list[ClusterNode], inventory: SystemInventory, config: dict[str, Any] | None = None) -> ClusterNode | None:
    local_ips = {
        value
        for value in (
            inventory.bootstrap_ipv4,
            inventory.bootstrap_ipv6,
            inventory.primary_lan_ip,
        )
        if value
    }
    local_names = {
        value.lower()
        for value in (inventory.hostname, inventory.fqdn)
        if value
    }

    for node in nodes:
        if node.name.lower() in local_names:
            return node
        if config:
            host = node_hostname(config, node)
            if host:
                host_short = host.split(".", 1)[0].lower()
                if host_short in local_names or host.lower() in local_names:
                    return node
        if any(ip in local_ips for ip in node.all_ips()):
            return node
    return None


def init_server_node(nodes: list[ClusterNode]) -> ClusterNode | None:
    for node in nodes:
        if node.role == "init-server":
            return node
    return None


def sort_nodes_for_install(nodes: list[ClusterNode]) -> list[ClusterNode]:
    order = {"init-server": 0, "server": 1, "agent": 2}
    return sorted(nodes, key=lambda node: (order.get(node.role, 9), node.name))


def all_node_tls_sans(nodes: list[ClusterNode], config: dict[str, Any] | None = None) -> list[str]:
    sans: list[str] = []
    for node in nodes:
        if config:
            host = node_hostname(config, node)
            if host and host not in sans:
                sans.append(host)
        for ip in node.all_ips():
            if ip not in sans:
                sans.append(ip)
    return sans
