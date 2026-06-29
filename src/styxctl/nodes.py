"""Styx cluster node definitions from styx.yaml."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
import socket
from typing import Any

from .inventory import SystemInventory

VALID_ROLES = frozenset({"init-server", "server", "agent"})


def resolve_hostname(hostname: str) -> str | None:
    try:
        results = socket.getaddrinfo(hostname, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except OSError:
        return None
    if not results:
        return None
    return results[0][4][0]


def node_dns_name(explicit_hostname: str | None) -> str | None:
    """Resolvable hostname for a node: its explicit hostname (its DuckDNS name), if set."""
    if isinstance(explicit_hostname, str) and explicit_hostname.strip():
        return explicit_hostname.strip()
    return None


def node_hostname(node: ClusterNode) -> str | None:
    """Resolvable hostname: the node's explicit hostname (its DuckDNS name), if any."""
    return node_dns_name(node.hostname)


@dataclass(slots=True)
class ClusterNode:
    name: str
    ipv4: str | None
    ipv6: str | None
    role: str
    hostname: str | None = None
    public_ipv4: str | None = None
    public_ipv6: str | None = None
    lan_ip: str | None = None
    site_index: int | None = None
    site_entrypoint: bool = False
    ssh_user: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def resolved_ipv4(self) -> str | None:
        host = node_bootstrap_host(self)
        if not host:
            return None
        try:
            return str(ipaddress.ip_address(host.split("%", 1)[0]))
        except ValueError:
            return resolve_hostname(host)

    def all_ips(self) -> list[str]:
        ips: list[str] = []
        if self.ipv4:
            ips.append(self.ipv4)
        if self.ipv6:
            ips.append(self.ipv6)
        return ips


def node_bootstrap_host(
    node: ClusterNode,
    *,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
) -> str | None:
    """Router WAN / port-forward target for cluster bootstrap connectivity."""
    if node.public_ipv4:
        return node.public_ipv4
    if inventory is not None and local_node is not None and node.name == local_node.name:
        from .network_detect import detect_public_ipv4

        return detect_public_ipv4()
    return None


def node_ssh_user(node: ClusterNode) -> str:
    """SSH login user for a node; defaults to the node name (hostname)."""
    if node.ssh_user and node.ssh_user.strip():
        return node.ssh_user.strip()
    return node.name


def parse_nodes(config: dict[str, Any]) -> list[ClusterNode]:
    raw_nodes = config.get("nodes")
    if raw_nodes is None:
        return []

    if not isinstance(raw_nodes, list):
        return []

    cluster = config.get("cluster", {})

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
        public_ipv4 = item.get("public_ipv4")
        public_ipv6 = item.get("public_ipv6")
        lan_ip = item.get("lan_ip")
        site_index_raw = item.get("site_index")
        site_entrypoint = item.get("site_entrypoint", False)
        user_field = item.get("ssh_user") or item.get("user")
        name_stripped = name.strip()
        site_index = site_index_raw if isinstance(site_index_raw, int) else None
        nodes.append(
            ClusterNode(
                name=name_stripped,
                ipv4=ipv4.strip() if isinstance(ipv4, str) and ipv4.strip() else None,
                ipv6=ipv6.strip() if isinstance(ipv6, str) and ipv6.strip() else None,
                role=role.strip(),
                hostname=host.strip() if isinstance(host, str) and host.strip() else None,
                public_ipv4=public_ipv4.strip() if isinstance(public_ipv4, str) and public_ipv4.strip() else None,
                public_ipv6=public_ipv6.strip() if isinstance(public_ipv6, str) and public_ipv6.strip() else None,
                lan_ip=lan_ip.strip() if isinstance(lan_ip, str) and lan_ip.strip() else None,
                site_index=site_index if site_index is not None and 0 <= site_index <= 255 else None,
                site_entrypoint=bool(site_entrypoint) if isinstance(site_entrypoint, bool) else False,
                ssh_user=user_field.strip() if isinstance(user_field, str) and user_field.strip() else name_stripped,
            )
        )
    return nodes


def sites_by_public_ip(nodes: list[ClusterNode]) -> dict[str, list[ClusterNode]]:
    sites: dict[str, list[ClusterNode]] = {}
    for node in nodes:
        if not node.public_ipv4:
            continue
        sites.setdefault(node.public_ipv4, []).append(node)
    return sites


def is_colocated(node: ClusterNode, nodes: list[ClusterNode]) -> bool:
    if not node.public_ipv4:
        return False
    return len(sites_by_public_ip(nodes).get(node.public_ipv4, [])) >= 2


def site_entrypoint_for(
    node: ClusterNode,
    nodes: list[ClusterNode],
    *,
    election_lan_ips: dict[str, str] | None = None,
    election_leader: str | None = None,
) -> ClusterNode | None:
    if not node.public_ipv4:
        return None

    site_nodes = sites_by_public_ip(nodes).get(node.public_ipv4, [])
    if len(site_nodes) == 1:
        return site_nodes[0]

    if election_leader:
        for site_node in site_nodes:
            if site_node.name == election_leader:
                return site_node

    explicit = [site_node for site_node in site_nodes if site_node.site_entrypoint]
    if len(explicit) == 1:
        return explicit[0]

    init_in_site = [site_node for site_node in site_nodes if site_node.role == "init-server"]
    if len(init_in_site) == 1:
        return init_in_site[0]

    return None


def node_effective_lan_ip(
    node: ClusterNode,
    *,
    election_lan_ips: dict[str, str] | None = None,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
) -> str | None:
    if node.lan_ip:
        return node.lan_ip
    if election_lan_ips:
        elected = election_lan_ips.get(node.name)
        if elected:
            return elected
    if inventory is not None and local_node is not None and node.name == local_node.name:
        from .network_detect import detect_lan_ipv4

        return detect_lan_ipv4(inventory)
    return None


def validate_nodes(
    nodes: list[ClusterNode],
    config: dict[str, Any] | None = None,
    *,
    election_lan_ips: dict[str, str] | None = None,
    election_leader: str | None = None,
    require_lan_ip: bool = False,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
) -> list[str]:
    errors: list[str] = []
    if not nodes:
        return errors

    init_servers = [node for node in nodes if node.role == "init-server"]
    if len(init_servers) != 1:
        errors.append("nodes: exactly one init-server node is required")

    seen_mesh_ips: set[str] = set()
    seen_single_site_hosts: set[str] = set()
    sites = sites_by_public_ip(nodes)

    for node in nodes:
        if node.role not in VALID_ROLES:
            errors.append(f"nodes.{node.name}.role: expected init-server, server, or agent")

        host = (
            node_bootstrap_host(
                node,
                inventory=inventory,
                local_node=local_node,
            )
            if config
            else node.public_ipv4
        )
        if not host:
            errors.append(
                f"nodes.{node.name}: set public_ipv4 (router WAN IP with port forwards) for bootstrap connectivity"
            )
        else:
            site_nodes = sites.get(host, [node])
            if len(site_nodes) == 1:
                if host in seen_single_site_hosts:
                    errors.append(f"nodes.{node.name}: duplicate bootstrap host {host}")
                else:
                    seen_single_site_hosts.add(host)

    for public_ip, site_nodes in sites.items():
        if len(site_nodes) < 2:
            continue

        entrypoint = site_entrypoint_for(
            site_nodes[0],
            nodes,
            election_lan_ips=election_lan_ips,
            election_leader=election_leader,
        )
        if entrypoint is None and election_leader:
            for site_node in site_nodes:
                if site_node.name == election_leader:
                    entrypoint = site_node
                    break

        for site_node in site_nodes:
            if entrypoint is not None and site_node.name == entrypoint.name:
                continue
            effective_lan_ip = node_effective_lan_ip(
                site_node,
                election_lan_ips=election_lan_ips,
                inventory=inventory,
                local_node=local_node,
            )
            if not effective_lan_ip:
                if require_lan_ip:
                    errors.append(
                        f"nodes.{site_node.name}: lan_ip is required for co-located nodes "
                        f"sharing public_ipv4 {public_ip}"
                    )

    from .network_plan import PISTYX_IPV4, PISTYX_IPV6

    reserved = {PISTYX_IPV4, PISTYX_IPV6}
    for node in nodes:
        if not node.ipv4 and not node.ipv6:
            errors.append(
                f"nodes.{node.name}: mesh ipv4 or ipv6 is required for k3s --node-ip"
            )
        for ip in node.all_ips():
            bare = ip.split("%", 1)[0]
            if bare in reserved:
                errors.append(f"nodes.{node.name}: uses the reserved pistyx egress address {bare}")
            if ip in seen_mesh_ips:
                errors.append(f"nodes.{node.name}: duplicate mesh IP {ip}")
            seen_mesh_ips.add(ip)
            try:
                ipaddress.ip_address(ip.split("%", 1)[0])
            except ValueError:
                errors.append(f"nodes.{node.name}: invalid mesh IP address {ip}")
    return errors


def validate_nodes_warnings(
    nodes: list[ClusterNode],
    config: dict[str, Any] | None = None,
    *,
    election_lan_ips: dict[str, str] | None = None,
    election_leader: str | None = None,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
) -> list[str]:
    warnings: list[str] = []
    if not nodes:
        return warnings

    sites = sites_by_public_ip(nodes)
    for public_ip, site_nodes in sites.items():
        if len(site_nodes) < 2:
            continue
        entrypoint = site_entrypoint_for(
            site_nodes[0],
            nodes,
            election_lan_ips=election_lan_ips,
            election_leader=election_leader,
        )
        for site_node in site_nodes:
            if entrypoint is not None and site_node.name == entrypoint.name:
                continue
            if not node_effective_lan_ip(
                site_node,
                election_lan_ips=election_lan_ips,
                inventory=inventory,
                local_node=local_node,
            ):
                warnings.append(
                    f"nodes.{site_node.name}: lan_ip unset; local election will fill it when "
                    f"styxctl runs on the LAN sharing public_ipv4 {public_ip}"
                )
    return warnings


def identify_local_node(nodes: list[ClusterNode], inventory: SystemInventory, config: dict[str, Any] | None = None) -> ClusterNode | None:
    from .network_detect import detect_lan_ipv4

    local_ips = {
        value
        for value in (
            inventory.bootstrap_ipv4,
            inventory.bootstrap_ipv6,
            inventory.primary_lan_ip,
            detect_lan_ipv4(inventory),
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
            host = node_hostname(node)
            if host:
                host_short = host.split(".", 1)[0].lower()
                if host_short in local_names or host.lower() in local_names:
                    return node

    for node in nodes:
        if any(ip in local_ips for ip in node.all_ips()):
            return node
    return None


def init_server_node(nodes: list[ClusterNode]) -> ClusterNode | None:
    for node in nodes:
        if node.role == "init-server":
            return node
    return None


def pistyx_holder(config: dict[str, Any] | None, nodes: list[ClusterNode]) -> ClusterNode | None:
    """The node currently holding the movable pistyx egress role.

    Decoupled from the init-server: honours `pistyx.current_host` when set, otherwise defaults
    to the init-server (today's static holder). Returns None if no candidate matches.
    """
    current = None
    if isinstance(config, dict):
        pistyx = config.get("pistyx")
        if isinstance(pistyx, dict):
            current = pistyx.get("current_host")
    if isinstance(current, str) and current.strip():
        for node in nodes:
            if node.name == current.strip():
                return node
    return init_server_node(nodes)


def sort_nodes_for_install(nodes: list[ClusterNode]) -> list[ClusterNode]:
    order = {"init-server": 0, "server": 1, "agent": 2}
    return sorted(nodes, key=lambda node: (order.get(node.role, 9), node.name))


def all_node_tls_sans(
    nodes: list[ClusterNode],
    config: dict[str, Any] | None = None,
    *,
    election_lan_ips: dict[str, str] | None = None,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
) -> list[str]:
    sans: list[str] = []
    for node in nodes:
        if node.public_ipv4 and node.public_ipv4 not in sans:
            sans.append(node.public_ipv4)
        if node.public_ipv6 and node.public_ipv6 not in sans:
            sans.append(node.public_ipv6)
        effective_lan_ip = node_effective_lan_ip(
            node,
            election_lan_ips=election_lan_ips,
            inventory=inventory,
            local_node=local_node,
        )
        if effective_lan_ip and effective_lan_ip not in sans:
            sans.append(effective_lan_ip)
        if config:
            host = node_hostname(node)
            if host and host not in sans:
                sans.append(host)
        for ip in node.all_ips():
            if ip not in sans:
                sans.append(ip)
    return sans
