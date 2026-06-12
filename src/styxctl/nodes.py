"""Styx cluster node definitions from styx.yaml."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
from typing import Any

from .inventory import SystemInventory

VALID_ROLES = frozenset({"init-server", "server", "agent"})


@dataclass(slots=True)
class ClusterNode:
    name: str
    ipv4: str | None
    ipv6: str | None
    role: str
    ssh_user: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @property
    def primary_ip(self) -> str | None:
        return self.ipv4 or self.ipv6

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
        ssh_user = item.get("ssh_user")
        nodes.append(
            ClusterNode(
                name=name.strip(),
                ipv4=ipv4.strip() if isinstance(ipv4, str) and ipv4.strip() else None,
                ipv6=ipv6.strip() if isinstance(ipv6, str) and ipv6.strip() else None,
                role=role.strip(),
                ssh_user=ssh_user.strip() if isinstance(ssh_user, str) and ssh_user.strip() else default_ssh_user,
            )
        )
    return nodes


def validate_nodes(nodes: list[ClusterNode]) -> list[str]:
    errors: list[str] = []
    if not nodes:
        return errors

    init_servers = [node for node in nodes if node.role == "init-server"]
    if len(init_servers) != 1:
        errors.append("nodes: exactly one init-server node is required")

    seen_ips: set[str] = set()
    for node in nodes:
        if node.role not in VALID_ROLES:
            errors.append(f"nodes.{node.name}.role: expected init-server, server, or agent")
        if not node.ipv4 and not node.ipv6:
            errors.append(f"nodes.{node.name}: at least one of ipv4 or ipv6 is required")
        for ip in node.all_ips():
            if ip in seen_ips:
                errors.append(f"nodes.{node.name}: duplicate node IP {ip}")
            seen_ips.add(ip)
            try:
                ipaddress.ip_address(ip.split("%", 1)[0])
            except ValueError:
                errors.append(f"nodes.{node.name}: invalid IP address {ip}")
    return errors


def identify_local_node(nodes: list[ClusterNode], inventory: SystemInventory) -> ClusterNode | None:
    local_ips = {
        value
        for value in (
            inventory.bootstrap_ipv4,
            inventory.bootstrap_ipv6,
            inventory.primary_lan_ip,
        )
        if value
    }
    for node in nodes:
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


def all_node_tls_sans(nodes: list[ClusterNode]) -> list[str]:
    sans: list[str] = []
    for node in nodes:
        for ip in node.all_ips():
            if ip not in sans:
                sans.append(ip)
    return sans
