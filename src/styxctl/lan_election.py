"""LAN leader election for co-located Styx gateway nodes.

When multiple devices share a LAN, they discover each other via UDP broadcast on
the Styx director port (47802) and elect the strongest node as that LAN's leader.
If the configured init-server is on the same LAN, the winner is promoted to
init-server and the previous init-server is demoted to server.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import copy
import ipaddress
import json
import os
import re
import socket
import threading
import time
from typing import Any

from .inventory import SystemInventory
from .nodes import identify_local_node, init_server_node, parse_nodes

DEFAULT_LAN_ELECTION_PORT = 47802
DEFAULT_COLLECT_SEC = 3.0
ANNOUNCE_INTERVAL_SEC = 0.5
MESSAGE_VERSION = 1

_ARCH_SCORES = {
    "x86_64": 1000,
    "amd64": 1000,
    "aarch64": 800,
    "arm64": 800,
    "armv8": 800,
    "armv7l": 400,
    "armv7": 400,
}


@dataclass(slots=True)
class LanElectionSettings:
    enabled: bool = False
    port: int = DEFAULT_LAN_ELECTION_PORT
    collect_sec: float = DEFAULT_COLLECT_SEC

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class LanPeer:
    node_name: str
    lan_ip: str
    strength: int
    hostname: str
    cluster_name: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class LanElectionResult:
    enabled: bool
    settings: LanElectionSettings
    local_peer: LanPeer | None = None
    peers: list[LanPeer] = field(default_factory=list)
    leader: LanPeer | None = None
    promote_to_init_server: bool = False
    previous_init_server: str | None = None
    subnet: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "settings": self.settings.to_dict(),
            "local_peer": self.local_peer.to_dict() if self.local_peer else None,
            "peers": [peer.to_dict() for peer in self.peers],
            "leader": self.leader.to_dict() if self.leader else None,
            "promote_to_init_server": self.promote_to_init_server,
            "previous_init_server": self.previous_init_server,
            "subnet": self.subnet,
            "warnings": list(self.warnings),
        }


def parse_lan_election_settings(config: dict[str, Any]) -> LanElectionSettings:
    cluster = config.get("cluster")
    if not isinstance(cluster, dict):
        return LanElectionSettings()

    leader_mode = cluster.get("leader", "static")
    enabled = isinstance(leader_mode, str) and leader_mode.strip().lower() == "lan-elected"

    port = DEFAULT_LAN_ELECTION_PORT
    collect_sec = DEFAULT_COLLECT_SEC
    lan_election = cluster.get("lan_election")
    if isinstance(lan_election, dict):
        raw_port = lan_election.get("port")
        if isinstance(raw_port, int) and 1 <= raw_port <= 65535:
            port = raw_port
        raw_collect = lan_election.get("collect_sec")
        if isinstance(raw_collect, (int, float)) and raw_collect > 0:
            collect_sec = float(raw_collect)

    return LanElectionSettings(enabled=enabled, port=port, collect_sec=collect_sec)


def parse_mem_total_kb(meminfo_text: str) -> int | None:
    for line in meminfo_text.splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    return None
    return None


def parse_root_avail_kb(df_text: str) -> int | None:
    for line in df_text.splitlines():
        if not line.startswith("/"):
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[5] == "/":
            try:
                return int(parts[3]) * 1024
            except ValueError:
                return None
    return None


def compute_node_strength(inventory: SystemInventory) -> int:
    score = 0

    mem_kb = parse_mem_total_kb(_read_proc_meminfo())
    if mem_kb:
        score += mem_kb // 1024

    cpu_count = os.cpu_count() or 1
    score += cpu_count * 500

    arch = inventory.architecture.lower()
    score += _ARCH_SCORES.get(arch, 200)

    if inventory.detected_binaries.get("k3s"):
        score += 250

    root_kb = parse_root_avail_kb(inventory.disk_usage)
    if root_kb:
        score += min(root_kb // (1024 * 1024), 2000)

    return score


def _read_proc_meminfo() -> str:
    try:
        with open("/proc/meminfo", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return ""


def parse_interface_ipv4(network_interfaces: list[str]) -> list[tuple[str, ipaddress.IPv4Network]]:
    parsed: list[tuple[str, ipaddress.IPv4Network]] = []
    for line in network_interfaces:
        for address, prefix in re.findall(r"\b(\d+\.\d+\.\d+\.\d+)/(\d+)\b", line):
            if address.startswith("127."):
                continue
            try:
                network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
            except ValueError:
                continue
            parsed.append((address, network))
    return parsed


def local_lan_subnet(inventory: SystemInventory) -> ipaddress.IPv4Network | None:
    interfaces = parse_interface_ipv4(inventory.network_interfaces)
    if not interfaces:
        return None

    if inventory.primary_lan_ip:
        for address, network in interfaces:
            if address == inventory.primary_lan_ip:
                return network

    for _address, network in interfaces:
        if not network.is_loopback:
            return network
    return None


def broadcast_address(subnet: ipaddress.IPv4Network) -> str:
    return str(subnet.broadcast_address)


def configured_node_names(config: dict[str, Any]) -> set[str]:
    return {node.name for node in parse_nodes(config)}


def filter_peers_to_configured_nodes(peers: list[LanPeer], config: dict[str, Any]) -> list[LanPeer]:
    allowed = configured_node_names(config)
    if not allowed:
        return []
    return [peer for peer in peers if peer.node_name in allowed]


def build_local_peer(
    config: dict[str, Any],
    inventory: SystemInventory,
    *,
    cluster_name: str | None = None,
) -> LanPeer | None:
    lan_ip = inventory.primary_lan_ip or inventory.bootstrap_ipv4
    if not lan_ip:
        return None

    nodes = parse_nodes(config)
    if not nodes:
        return None

    local_node = identify_local_node(nodes, inventory, config)
    if local_node is None:
        return None

    cluster = config.get("cluster", {})
    name = cluster_name
    if not isinstance(name, str) or not name.strip():
        raw = cluster.get("name") if isinstance(cluster, dict) else None
        name = raw if isinstance(raw, str) and raw.strip() else "styx"

    return LanPeer(
        node_name=local_node.name,
        lan_ip=lan_ip,
        strength=compute_node_strength(inventory),
        hostname=inventory.hostname,
        cluster_name=name.strip(),
    )


def _encode_message(payload: dict[str, object]) -> bytes:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return body


def _decode_message(data: bytes) -> dict[str, object] | None:
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _peer_from_payload(payload: dict[str, object]) -> LanPeer | None:
    if payload.get("version") != MESSAGE_VERSION:
        return None
    if payload.get("type") not in {"announce", "response"}:
        return None

    node_name = payload.get("node")
    lan_ip = payload.get("lan_ip")
    strength = payload.get("strength")
    hostname = payload.get("hostname")
    cluster_name = payload.get("cluster")

    if not all(isinstance(value, str) and value.strip() for value in (node_name, lan_ip, hostname, cluster_name)):
        return None
    if not isinstance(strength, int):
        return None

    return LanPeer(
        node_name=node_name.strip(),
        lan_ip=lan_ip.strip(),
        strength=strength,
        hostname=hostname.strip(),
        cluster_name=cluster_name.strip(),
    )


def _announce_payload(peer: LanPeer, *, message_type: str) -> dict[str, object]:
    return {
        "version": MESSAGE_VERSION,
        "type": message_type,
        "cluster": peer.cluster_name,
        "node": peer.node_name,
        "lan_ip": peer.lan_ip,
        "hostname": peer.hostname,
        "strength": peer.strength,
    }


def discover_lan_peers(
    settings: LanElectionSettings,
    inventory: SystemInventory,
    *,
    local_peer: LanPeer,
    subnet: ipaddress.IPv4Network | None = None,
) -> list[LanPeer]:
    subnet = subnet or local_lan_subnet(inventory)
    if subnet is None:
        return [local_peer]

    peers: dict[str, LanPeer] = {local_peer.node_name: local_peer}
    stop = threading.Event()

    def listen() -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", settings.port))
            sock.settimeout(0.2)
            while not stop.is_set():
                try:
                    data, _addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break

                payload = _decode_message(data)
                if payload is None:
                    continue
                if payload.get("cluster") != local_peer.cluster_name:
                    continue

                peer = _peer_from_payload(payload)
                if peer is None:
                    continue
                try:
                    ipaddress.ip_address(peer.lan_ip)
                except ValueError:
                    continue
                if ipaddress.ip_address(peer.lan_ip) not in subnet:
                    continue
                peers[peer.node_name] = peer

                if payload.get("type") == "announce":
                    response = _encode_message(_announce_payload(local_peer, message_type="response"))
                    try:
                        sock.sendto(response, (peer.lan_ip, settings.port))
                    except OSError:
                        pass
        finally:
            sock.close()

    listener = threading.Thread(target=listen, daemon=True)
    listener.start()

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        target = (broadcast_address(subnet), settings.port)
        deadline = time.monotonic() + settings.collect_sec
        while time.monotonic() < deadline:
            payload = _encode_message(_announce_payload(local_peer, message_type="announce"))
            try:
                send_sock.sendto(payload, target)
            except OSError:
                break
            time.sleep(ANNOUNCE_INTERVAL_SEC)
    finally:
        send_sock.close()
        stop.set()
        listener.join(timeout=1.0)

    return sorted(peers.values(), key=lambda peer: (-peer.strength, peer.node_name))


def elect_lan_leader(peers: list[LanPeer]) -> LanPeer | None:
    if not peers:
        return None
    return max(peers, key=lambda peer: (peer.strength, peer.node_name))


def run_lan_election(
    config: dict[str, Any],
    inventory: SystemInventory,
    settings: LanElectionSettings | None = None,
) -> LanElectionResult:
    settings = settings or parse_lan_election_settings(config)
    if not settings.enabled:
        return LanElectionResult(enabled=False, settings=settings)

    subnet = local_lan_subnet(inventory)
    local_peer = build_local_peer(config, inventory)
    if local_peer is None:
        return LanElectionResult(
            enabled=True,
            settings=settings,
            warnings=["local host is not listed in styx.yaml nodes or LAN address is unknown"],
        )

    peers = discover_lan_peers(settings, inventory, local_peer=local_peer, subnet=subnet)
    discovered_count = len(peers)
    peers = filter_peers_to_configured_nodes(peers, config)
    leader = elect_lan_leader(peers)

    nodes = parse_nodes(config)
    init_node = init_server_node(nodes)
    init_on_lan = init_node is not None and init_node.name in {peer.node_name for peer in peers}
    promote = len(peers) >= 2 and init_on_lan and leader is not None

    result = LanElectionResult(
        enabled=True,
        settings=settings,
        local_peer=local_peer,
        peers=peers,
        leader=leader,
        promote_to_init_server=promote,
        previous_init_server=init_node.name if promote and init_node and leader and leader.node_name != init_node.name else None,
        subnet=str(subnet) if subnet else None,
    )

    if discovered_count > len(peers):
        result.warnings.append(
            "ignored LAN peer(s) not listed in styx.yaml nodes"
        )
    if len(peers) < 2:
        result.warnings.append("only one Styx peer on this LAN; keeping configured roles")
    elif not init_on_lan:
        result.warnings.append(
            "init-server is not on this LAN; elected leader coordinates locally but k3s roles stay unchanged"
        )

    return result


def apply_lan_election_roles(config: dict[str, Any], election: LanElectionResult) -> dict[str, Any]:
    if not election.enabled or not election.promote_to_init_server or election.leader is None:
        return config

    effective = copy.deepcopy(config)
    raw_nodes = effective.get("nodes")
    if not isinstance(raw_nodes, list):
        return config

    leader_name = election.leader.node_name
    for item in raw_nodes:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str):
            continue
        if name == leader_name:
            item["role"] = "init-server"
        elif item.get("role") == "init-server":
            item["role"] = "server"

    return effective


def resolve_lan_leadership(
    config: dict[str, Any],
    inventory: SystemInventory,
) -> tuple[dict[str, Any], LanElectionResult]:
    election = run_lan_election(config, inventory)
    if not election.enabled:
        return config, election
    return apply_lan_election_roles(config, election), election
