"""Styx backbone WireGuard mesh — hub-and-spoke with the init-server as the hub.

Topology: the init-server is the WG server (hub); every other k3s node is a spoke that
peers ONLY with the hub. Spokes route the whole Styx supernet (`10.0.0.0/14` + the IPv6
supernet) through the hub, which enables `ip_forward` and routes between spokes via their
per-spoke `/32` (+`/128`) peer entries. The mesh node IPs are the flat `10.0.0.0/16`
addresses `assign_node_mesh_ips` already assigns (`10.0.0.1`=init, `.2`, …).

Key handling: each node keeps its OWN private key (in its `/etc/wireguard/<iface>.conf`,
written by install). `styxctl mesh up` (on the init-server) only collects PUBLIC keys over
the gateway SSH port, builds the roster, and has each node render its own `[Peer]` blocks
locally (`mesh apply-local`) — private keys never leave their node.
"""

from __future__ import annotations

import base64
import json
import shlex
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

KEEPALIVE_SECONDS = 25
SITE_INTERFACE_PREFIX = "StyxSite"
SITE_WG_PORT_BASE = 47820
SITE_WG_PORT_END = 47850
RunResult = tuple[bool, str]


@dataclass(slots=True)
class MeshMember:
    name: str
    role: str
    ipv4: str | None          # mesh overlay IP (10.0.0.x)
    ipv6: str | None
    public_key: str | None = None   # filled by `mesh up`; placeholder in `mesh plan`
    endpoint: str | None = None      # hub's reachable host as seen by a spoke (host only)


@dataclass(slots=True)
class SiteMember:
    name: str
    role: str
    site_index: int
    host_suffix: int
    ipv4: str | None
    ipv6: str | None
    public_key: str | None = None
    endpoint: str | None = None      # site entrypoint host as seen by this node


# --------------------------------------------------------------------------- render (pure)

def render_local_config(
    local_name: str,
    private_key: str,
    members: list[MeshMember],
    init_name: str,
    *,
    listen_port: int,
    route_v4: str | None,
    route_v6: str | None,
) -> str:
    """Render one node's full WireGuard config (Interface + Peers) for the hub-and-spoke mesh."""
    by_name = {m.name: m for m in members}
    local = by_name[local_name]
    init = by_name.get(init_name)

    lines = ["[Interface]", f"PrivateKey = {private_key}"]
    addr = [f"{local.ipv4}/32"] if local.ipv4 else []
    if local.ipv6:
        addr.append(f"{local.ipv6}/128")
    if addr:
        lines.append(f"Address = {', '.join(addr)}")
    lines.append(f"ListenPort = {listen_port}")
    lines.append("")

    if local_name == init_name:
        # Hub: one [Peer] per spoke, routed by the spoke's own /32 (+/128).
        for member in members:
            if member.name == init_name:
                continue
            allowed = [f"{member.ipv4}/32"] if member.ipv4 else []
            if member.ipv6:
                allowed.append(f"{member.ipv6}/128")
            if not allowed:
                continue
            lines += [
                "[Peer]",
                f"# {member.name} ({member.role})",
                f"PublicKey = {member.public_key}",
                f"AllowedIPs = {', '.join(allowed)}",
                "",
            ]
    elif init is not None:
        # Spoke: a single [Peer] = the hub; route the whole Styx supernet through it.
        route = [r for r in (route_v4, route_v6) if r]
        lines += ["[Peer]", f"# {init.name} (hub)", f"PublicKey = {init.public_key}"]
        if init.endpoint:
            lines.append(f"Endpoint = {init.endpoint}:{listen_port}")
        lines.append(f"AllowedIPs = {', '.join(route)}")
        lines.append(f"PersistentKeepalive = {KEEPALIVE_SECONDS}")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_site_config(
    local_name: str,
    private_key: str,
    members: list[SiteMember],
    entrypoint_name: str,
    *,
    listen_port: int,
    network_v4: str | None,
    network_v6: str | None,
    stack_mode: str = "dual-stack",
) -> str:
    """Render one physical-site overlay.

    Every Pi gets a config for every site. The site's entrypoint routes individual Pi
    addresses; all other Pis route that site subnet to the entrypoint. This keeps
    10.0.N.X stable for a Pi even when it is not currently at site N.
    """
    by_name = {m.name: m for m in members}
    local = by_name[local_name]
    entrypoint = by_name.get(entrypoint_name)
    want_v4 = stack_mode in {"dual-stack", "ipv4-only"}
    want_v6 = stack_mode in {"dual-stack", "ipv6-only"}

    lines = ["[Interface]", f"PrivateKey = {private_key}"]
    addr: list[str] = []
    if want_v4 and local.ipv4:
        addr.append(f"{local.ipv4}/24")
    if want_v6 and local.ipv6:
        addr.append(f"{local.ipv6}/64")
    if addr:
        lines.append(f"Address = {', '.join(addr)}")
    lines.append(f"ListenPort = {listen_port}")
    lines.append("")

    if local_name == entrypoint_name:
        for member in members:
            if member.name == entrypoint_name:
                continue
            allowed = []
            if want_v4 and member.ipv4:
                allowed.append(f"{member.ipv4}/32")
            if want_v6 and member.ipv6:
                allowed.append(f"{member.ipv6}/128")
            if not allowed:
                continue
            lines += [
                "[Peer]",
                f"# {member.name} ({member.role})",
                f"PublicKey = {member.public_key}",
                f"AllowedIPs = {', '.join(allowed)}",
                "",
            ]
    elif entrypoint is not None:
        route = []
        if want_v4 and network_v4:
            route.append(network_v4)
        if want_v6 and network_v6:
            route.append(network_v6)
        lines += [
            "[Peer]",
            f"# {entrypoint.name} (site {entrypoint.site_index} entrypoint)",
            f"PublicKey = {entrypoint.public_key}",
        ]
        if entrypoint.endpoint:
            lines.append(f"Endpoint = {entrypoint.endpoint}:{listen_port}")
        lines.append(f"AllowedIPs = {', '.join(route)}")
        lines.append(f"PersistentKeepalive = {KEEPALIVE_SECONDS}")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_pistyx_pop(
    private_key: str,
    clients: list[dict[str, Any]],
    *,
    listen_port: int,
    mtu: int,
    gateway_v4: str | None,
    gateway_v6: str | None,
    stack_mode: str = "dual-stack",
) -> str:
    """Render a leader's pistyx PoP interface — the client entry point clients hit.

    Every site's leader binds this SAME interface: the SHARED pistyx private key + that site's
    pistyx service address as a host route, with one [Peer] per mobile client. A DuckDNS
    repoint of pistyx.duckdns.org therefore moves a client to whichever leader becomes
    active with zero client reconfig. The leader LOCAL-NATs the client range out its OWN WAN
    (local breakout, handled out-of-band by ensure_egress_nat) — styx never carries client traffic.
    """
    want_v4 = stack_mode in {"dual-stack", "ipv4-only"}
    want_v6 = stack_mode in {"dual-stack", "ipv6-only"}

    lines = ["[Interface]", f"PrivateKey = {private_key}"]
    addr: list[str] = []
    if want_v4 and gateway_v4:
        addr.append(f"{gateway_v4}/32")
    if want_v6 and gateway_v6:
        addr.append(f"{gateway_v6}/128")
    if addr:
        lines.append(f"Address = {', '.join(addr)}")
    lines.append(f"ListenPort = {listen_port}")
    lines.append(f"MTU = {mtu}")
    lines.append("")

    for client in clients:
        allowed = []
        if want_v4 and client.get("ipv4"):
            allowed.append(f"{client['ipv4']}/32")
        if want_v6 and client.get("ipv6"):
            allowed.append(f"{client['ipv6']}/128")
        if not allowed or not client.get("public_key"):
            continue
        lines += [
            "[Peer]",
            f"# client: {client.get('name', '?')}",
            f"PublicKey = {client['public_key']}",
            f"AllowedIPs = {', '.join(allowed)}",
            "",
        ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- roster from config

def _routes(config: dict[str, Any]) -> tuple[str | None, str | None]:
    network = config.get("network", {})
    return network.get("ipv4_supernet"), network.get("ipv6_supernet")


def mesh_members(config: dict[str, Any]) -> tuple[list[MeshMember], str | None]:
    """Build mesh members (mesh IPs + roles) from the config; return (members, init_name)."""
    from .nodes import init_server_node, parse_nodes

    nodes = parse_nodes(config)
    init = init_server_node(nodes)
    members = [
        MeshMember(name=n.name, role=n.role, ipv4=n.ipv4, ipv6=n.ipv6)
        for n in nodes
    ]
    return members, (init.name if init else None)


def _wg_settings(config: dict[str, Any]) -> tuple[str, int]:
    wg = config.get("wireguard", {})
    interface = wg.get("interface", "Styx")
    port = wg.get("port", 47800)
    return (interface if isinstance(interface, str) else "Styx"), (port if isinstance(port, int) else 47800)


def _explicit_site_index(node: Any) -> int | None:
    site_index = getattr(node, "site_index", None)
    return site_index if isinstance(site_index, int) and 0 <= site_index <= 255 else None


def _site_index_for_node(nodes: list[Any], node: Any | None) -> int:
    """Return the site's third-octet index for a node.

    A site is a place/WAN boundary: nodes with the same public_ipv4 share one site. An explicit
    `site_index` on any node in that public-IP group labels the whole site. Without an explicit
    label, distinct public IPs get 1-based site indexes in first-seen order. As a last fallback,
    node order becomes site order.
    """
    if node is None:
        from .network_plan import ROADWARRIOR_SITE_INDEX

        return ROADWARRIOR_SITE_INDEX

    def site_key(candidate: Any, idx: int) -> str:
        public_ip = getattr(candidate, "public_ipv4", None)
        if isinstance(public_ip, str) and public_ip.strip():
            return f"public:{public_ip.strip()}"
        return f"node:{getattr(candidate, 'name', idx)}"

    key_order: list[str] = []
    explicit_by_key: dict[str, int] = {}

    for idx, candidate in enumerate(nodes):
        key = site_key(candidate, idx)
        if key not in key_order:
            key_order.append(key)
        explicit_candidate = _explicit_site_index(candidate)
        if explicit_candidate is not None and key not in explicit_by_key:
            explicit_by_key[key] = explicit_candidate

    used_indexes = set(explicit_by_key.values())
    site_by_key = dict(explicit_by_key)
    next_site = 1
    for key in key_order:
        if key in site_by_key:
            continue
        while next_site in used_indexes:
            next_site += 1
        site_by_key[key] = next_site
        used_indexes.add(next_site)
        next_site += 1

    fallback_by_name: dict[str, int] = {}
    for idx, candidate in enumerate(nodes):
        fallback_by_name[candidate.name] = site_by_key[site_key(candidate, idx)]
    return fallback_by_name.get(node.name, 1)


def _site_scope_for_node(nodes: list[Any], node: Any | None) -> dict[str, str | int]:
    from .network_plan import (
        pistyx_ipv4_for_site,
        pistyx_ipv6_for_site,
        site_ipv4_network,
        site_ipv6_network,
    )

    site_index = _site_index_for_node(nodes, node)
    return {
        "site_index": site_index,
        "gateway_v4": pistyx_ipv4_for_site(site_index),
        "gateway_v6": pistyx_ipv6_for_site(site_index),
        "network_v4": site_ipv4_network(site_index),
        "network_v6": site_ipv6_network(site_index),
    }


def _site_indexes_for_nodes(nodes: list[Any]) -> list[int]:
    indexes: list[int] = []
    for node in nodes:
        site_index = _site_index_for_node(nodes, node)
        if site_index not in indexes:
            indexes.append(site_index)
    return indexes


def _site_nodes_by_index(nodes: list[Any]) -> dict[int, list[Any]]:
    grouped: dict[int, list[Any]] = {}
    for node in nodes:
        grouped.setdefault(_site_index_for_node(nodes, node), []).append(node)
    return grouped


def _site_entrypoint_for_index(
    nodes: list[Any],
    site_index: int,
    *,
    election_leader: str | None = None,
) -> Any | None:
    site_nodes = _site_nodes_by_index(nodes).get(site_index, [])
    if not site_nodes:
        return None
    if election_leader:
        elected = next((node for node in site_nodes if node.name == election_leader), None)
        if elected is not None:
            return elected
    explicit = [node for node in site_nodes if getattr(node, "site_entrypoint", False)]
    if len(explicit) == 1:
        return explicit[0]
    init = [node for node in site_nodes if getattr(node, "role", "") == "init-server"]
    if len(init) == 1:
        return init[0]
    return site_nodes[0]


def _site_interface(site_index: int) -> str:
    return f"{SITE_INTERFACE_PREFIX}{site_index}"


def _site_overlay_port(site_index: int, ordinal: int) -> int:
    site_port = SITE_WG_PORT_BASE + site_index
    if SITE_WG_PORT_BASE <= site_port <= SITE_WG_PORT_END:
        return site_port
    return min(SITE_WG_PORT_BASE + ordinal, SITE_WG_PORT_END)


def _site_members_for_index(
    nodes: list[Any],
    site_index: int,
    pubkeys: dict[str, str] | None = None,
    *,
    entrypoint_name: str | None = None,
    entrypoint_endpoint: str | None = None,
    stack_mode: str = "dual-stack",
) -> list[SiteMember]:
    from .network_plan import node_host_suffix_for_index, node_ipv4_for_site, node_ipv6_for_site

    want_v4 = stack_mode in {"dual-stack", "ipv4-only"}
    want_v6 = stack_mode in {"dual-stack", "ipv6-only"}
    members: list[SiteMember] = []
    for index, node in enumerate(nodes):
        suffix = node_host_suffix_for_index(index)
        members.append(
            SiteMember(
                name=node.name,
                role=node.role,
                site_index=site_index,
                host_suffix=suffix,
                ipv4=node_ipv4_for_site(index, site_index=site_index) if want_v4 else None,
                ipv6=node_ipv6_for_site(index, site_index=site_index) if want_v6 else None,
                public_key=(pubkeys or {}).get(node.name, f"<pubkey:{node.name}>"),
                endpoint=entrypoint_endpoint if node.name == entrypoint_name else None,
            )
        )
    return members


def _site_endpoint(
    entrypoint: Any,
    dialer: Any,
    *,
    election_lan_ips: dict[str, str] | None,
    inventory: Any,
    local_node: Any | None,
) -> str | None:
    from .nodes import node_effective_lan_ip

    colocated = bool(
        getattr(entrypoint, "public_ipv4", None)
        and getattr(dialer, "public_ipv4", None)
        and entrypoint.public_ipv4 == dialer.public_ipv4
    )
    if colocated:
        lan = node_effective_lan_ip(
            entrypoint,
            election_lan_ips=election_lan_ips,
            inventory=inventory,
            local_node=local_node,
        )
        if lan:
            return lan
    return getattr(entrypoint, "hostname", None) or getattr(entrypoint, "public_ipv4", None) or entrypoint.name


def _site_overlay_blocks(
    nodes: list[Any],
    *,
    pubkeys: dict[str, str] | None,
    stack_mode: str,
    dialer: Any | None = None,
    election_lan_ips: dict[str, str] | None = None,
    election_leader: str | None = None,
    inventory: Any = None,
    local_node: Any | None = None,
) -> list[dict[str, Any]]:
    from .network_plan import site_ipv4_network, site_ipv6_network

    blocks: list[dict[str, Any]] = []
    for ordinal, site_index in enumerate(_site_indexes_for_nodes(nodes)):
        entrypoint = _site_entrypoint_for_index(nodes, site_index, election_leader=election_leader)
        if entrypoint is None:
            continue
        endpoint = None
        if dialer is None:
            endpoint = getattr(entrypoint, "hostname", None) or getattr(entrypoint, "public_ipv4", None) or entrypoint.name
        elif dialer.name != entrypoint.name:
            endpoint = _site_endpoint(
                entrypoint,
                dialer,
                election_lan_ips=election_lan_ips,
                inventory=inventory,
                local_node=local_node,
            )
        members = _site_members_for_index(
            nodes,
            site_index,
            pubkeys,
            entrypoint_name=entrypoint.name,
            entrypoint_endpoint=endpoint,
            stack_mode=stack_mode,
        )
        blocks.append(
            {
                "site_index": site_index,
                "interface": _site_interface(site_index),
                "port": _site_overlay_port(site_index, ordinal),
                "entrypoint": entrypoint.name,
                "network_v4": site_ipv4_network(site_index),
                "network_v6": site_ipv6_network(site_index),
                "stack_mode": stack_mode,
                "members": [asdict(member) for member in members],
            }
        )
    return blocks


# --------------------------------------------------------------------------- local key helpers

def _conf_path(interface: str) -> Path:
    return Path("/etc/wireguard") / f"{interface}.conf"


def _read_private_key(interface: str) -> str | None:
    try:
        text = subprocess.run(
            ["sudo", "cat", str(_conf_path(interface))],
            check=False, capture_output=True, text=True, timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in text.splitlines():
        if line.strip().startswith("PrivateKey"):
            return line.split("=", 1)[1].strip()
    return None


def _gen_private_key() -> str | None:
    if shutil.which("wg") is None:
        return None
    out = subprocess.run(["wg", "genkey"], check=False, capture_output=True, text=True, timeout=10)
    return out.stdout.strip() or None


def _public_key(private_key: str) -> str | None:
    if shutil.which("wg") is None:
        return None
    out = subprocess.run(
        ["wg", "pubkey"], input=private_key, check=False, capture_output=True, text=True, timeout=10
    )
    return out.stdout.strip() or None


def _write_conf(interface: str, content: str) -> RunResult:
    from .remediation import _run_mutating

    tmp = Path("/tmp") / f"styx-mesh-{interface}.conf"
    try:
        tmp.write_text(content, encoding="utf-8")
    except OSError as exc:
        return False, str(exc)
    for cmd in (
        ["mkdir", "-p", "/etc/wireguard"],
        ["cp", str(tmp), str(_conf_path(interface))],
        ["chmod", "600", str(_conf_path(interface))],
    ):
        ok, detail = _run_mutating(cmd, use_sudo=True, sudo_available=True)
        if not ok:
            return False, detail
    tmp.unlink(missing_ok=True)
    return True, f"wrote {_conf_path(interface)}"


def ensure_local_keypair(config: dict[str, Any]) -> tuple[bool, str]:
    """Ensure this node has a WG private key; return (ok, public_key_or_error)."""
    interface, _port = _wg_settings(config)
    private = _read_private_key(interface)
    if private is None:
        private = _gen_private_key()
        if private is None:
            return False, "wg not available to generate a key"
        ok, detail = _write_conf(interface, f"[Interface]\nPrivateKey = {private}\n")
        if not ok:
            return False, detail
    public = _public_key(private)
    if public is None:
        return False, "could not derive public key (is wireguard-tools installed?)"
    return True, public


# --------------------------------------------------------------------------- local apply

def apply_local(
    roster: dict[str, Any],
    config: dict[str, Any] | None = None,
    *,
    local_name: str | None = None,
) -> tuple[dict[str, Any], int]:
    """Render and install THIS node's mesh config from the roster (run on each node).

    The roster is self-contained (carries `interface`/`port`/`route_*`), and `mesh up`
    passes `local_name` explicitly — so this works over SSH in any cwd with no local
    styx.yaml. `config`/identify-by-inventory is only the fallback for manual invocation.
    """
    config = config or {}
    report: dict[str, Any] = {"status": "OK", "actions": []}
    interface = roster.get("interface") or _wg_settings(config)[0]
    port = roster.get("port") or _wg_settings(config)[1]

    members = [MeshMember(**m) for m in roster.get("members", [])]
    init_name = roster.get("init_name")
    if not members or not init_name:
        report["status"] = "ERROR"
        report["message"] = "roster missing members/init_name"
        return report, 1

    if local_name is None:
        from .inventory import collect_inventory
        from .nodes import identify_local_node, parse_nodes

        local_node = identify_local_node(parse_nodes(config), collect_inventory(), config)
        local_name = local_node.name if local_node else None
    if local_name not in {m.name for m in members}:
        report["status"] = "ERROR"
        report["message"] = f"local node {local_name!r} not in roster"
        return report, 1

    private = _read_private_key(interface)
    if private is None:
        report["status"] = "ERROR"
        report["message"] = f"no PrivateKey in {_conf_path(interface)} — run install or `mesh pubkey-local` first"
        return report, 1

    route_v4, route_v6 = roster.get("route_v4"), roster.get("route_v6")
    content = render_local_config(
        local_name, private, members, init_name,
        listen_port=port, route_v4=route_v4, route_v6=route_v6,
    )
    ok, detail = _write_conf(interface, content)
    report["actions"].append(detail)
    if not ok:
        report["status"] = "ERROR"
        report["message"] = detail
        return report, 1

    # Reload the interface (syncconf keeps it up without dropping the handshake when possible).
    from .remediation import _run_mutating

    synced, sdetail = _run_mutating(
        ["bash", "-c", f"wg-quick strip {interface} | wg syncconf {interface} /dev/stdin || wg-quick up {interface}"],
        use_sudo=True, sudo_available=True,
    )
    report["actions"].append(sdetail if synced else f"reload failed: {sdetail}")

    site_ok = True
    for overlay in roster.get("site_overlays", []):
        if not isinstance(overlay, dict):
            continue
        site_interface = overlay.get("interface")
        entrypoint = overlay.get("entrypoint")
        if not isinstance(site_interface, str) or not isinstance(entrypoint, str):
            report["status"] = "ERROR"
            report["message"] = "site overlay missing interface/entrypoint"
            return report, 1
        site_members = [SiteMember(**m) for m in overlay.get("members", [])]
        if local_name not in {m.name for m in site_members}:
            report["status"] = "ERROR"
            report["message"] = f"local node {local_name!r} not in site overlay {site_interface}"
            return report, 1
        site_content = render_site_config(
            local_name,
            private,
            site_members,
            entrypoint,
            listen_port=int(overlay.get("port", SITE_WG_PORT_BASE)),
            network_v4=overlay.get("network_v4"),
            network_v6=overlay.get("network_v6"),
            stack_mode=overlay.get("stack_mode", "dual-stack"),
        )
        ok, detail = _write_conf(site_interface, site_content)
        report["actions"].append(detail)
        if not ok:
            report["status"] = "ERROR"
            report["message"] = detail
            return report, 1
        reloaded, rdetail = _run_mutating(
            [
                "bash",
                "-c",
                f"wg-quick strip {site_interface} | wg syncconf {site_interface} /dev/stdin || wg-quick up {site_interface}",
            ],
            use_sudo=True,
            sudo_available=True,
        )
        report["actions"].append(rdetail if reloaded else f"{site_interface} reload failed: {rdetail}")
        site_ok = site_ok and reloaded

    pop = roster.get("pistyx_pop")
    pop_ok = True
    if isinstance(pop, dict) and pop.get("is_leader"):
        pop_ok, pop_detail = apply_pistyx_pop(pop)
        report["actions"].append(pop_detail)
    else:
        egress_interface = roster.get("pistyx_interface")
        if isinstance(egress_interface, str) and egress_interface:
            down_ok, down_detail = _run_mutating(
                ["bash", "-c", f"wg-quick down {egress_interface} 2>/dev/null || true"],
                use_sudo=True,
                sudo_available=True,
            )
            report["actions"].append(
                f"pistyx PoP down/no-op: {down_detail}" if down_ok else f"pistyx PoP down failed: {down_detail}"
            )

    role = "hub" if local_name == init_name else "spoke"
    report["message"] = f"{local_name} mesh applied ({role})"
    return report, (0 if (synced and site_ok and pop_ok) else 1)


# --------------------------------------------------------------------------- plan (preview)

def mesh_plan(config_path: str | Path | None = None) -> tuple[dict[str, Any], int]:
    from .config import find_config, load_config, resolve_config
    from .nodes import parse_nodes, init_server_node

    candidate = Path(config_path) if config_path is not None else find_config()
    if candidate is None:
        return {"status": "ERROR", "message": "no styx.yaml found"}, 1
    config = resolve_config(load_config(candidate))
    members, init_name = mesh_members(config)
    if init_name is None:
        return {"status": "ERROR", "message": "no init-server node in config"}, 1

    interface, port = _wg_settings(config)
    route_v4, route_v6 = _routes(config)
    nodes = parse_nodes(config)
    init_node = init_server_node(nodes)
    init_host = (init_node.hostname or init_node.public_ipv4 or init_node.name) if init_node else "<init-endpoint>"
    from .network_plan import cluster_stack_mode

    stack = cluster_stack_mode(config)

    # Placeholder keys + a single representative hub endpoint for preview.
    for member in members:
        member.public_key = f"<pubkey:{member.name}>"
        if member.name == init_name:
            member.endpoint = init_host

    site_blocks = _site_overlay_blocks(nodes, pubkeys=None, stack_mode=stack)
    site_configs: dict[str, dict[str, str]] = {node.name: {} for node in nodes}
    for block in site_blocks:
        site_members = [SiteMember(**m) for m in block["members"]]
        for node in nodes:
            site_configs[node.name][block["interface"]] = render_site_config(
                node.name,
                f"<privkey:{node.name}>",
                site_members,
                block["entrypoint"],
                listen_port=int(block["port"]),
                network_v4=block["network_v4"],
                network_v6=block["network_v6"],
                stack_mode=stack,
            )

    report: dict[str, Any] = {
        "status": "OK",
        "interface": interface,
        "hub": init_name,
        "spokes": [m.name for m in members if m.name != init_name],
        "route": [r for r in (route_v4, route_v6) if r],
        "site_overlays": [
            {
                key: block[key]
                for key in ("site_index", "interface", "port", "entrypoint", "network_v4", "network_v6")
            }
            for block in site_blocks
        ],
        "site_configs": {name: configs for name, configs in site_configs.items() if configs},
        "configs": {
            m.name: render_local_config(
                m.name, f"<privkey:{m.name}>", members, init_name,
                listen_port=port, route_v4=route_v4, route_v6=route_v6,
            )
            for m in members
        },
    }

    # pistyx PoP preview: the client entry interface each leader runs (shared identity + clients).
    from .nodes import pistyx_holder

    eg_interface, eg_port, eg_mtu, eg_hostname = _egress_settings(config)
    holder = pistyx_holder(config, nodes)
    holder_name = holder.name if holder else None
    holder_scope = _site_scope_for_node(nodes, holder)
    clients = pistyx_clients(config, site_index=int(holder_scope["site_index"]))
    report["pistyx"] = holder_name
    report["pistyx_hostname"] = eg_hostname
    report["pistyx_site_index"] = holder_scope["site_index"]
    report["egress_interface"] = eg_interface
    report["egress_configs"] = (
        {
            holder_name: render_pistyx_pop(
                "<privkey:pistyx>", clients,
                listen_port=eg_port, mtu=eg_mtu,
                gateway_v4=str(holder_scope["gateway_v4"]),
                gateway_v6=str(holder_scope["gateway_v6"]),
                stack_mode=stack,
            )
        }
        if holder_name
        else {}
    )
    return report, 0


# --------------------------------------------------------------------------- orchestration

def _hub_endpoint(
    init: ClusterNode,
    spoke: ClusterNode,
    *,
    election_lan_ips: dict[str, str] | None,
    inventory: Any,
    local_node: ClusterNode | None,
) -> str | None:
    """The hub host a spoke dials. Detected DuckDNS hostname for a REMOTE spoke (dynamic —
    never a pinned public IP, so it follows the per-site DuckDNS publisher), or the hub's
    LAN IP for a COLOCATED spoke (the name would resolve to the public IP and hairpin NAT)."""
    from .nodes import node_effective_lan_ip

    colocated = bool(init.public_ipv4 and spoke.public_ipv4 and init.public_ipv4 == spoke.public_ipv4)
    if colocated:
        lan = node_effective_lan_ip(
            init, election_lan_ips=election_lan_ips, inventory=inventory, local_node=local_node
        )
        if lan:
            return lan
    return init.hostname or init.public_ipv4


def mesh_up(config_path: str | Path | None = None) -> tuple[dict[str, Any], int]:
    """Collect public keys over SSH, build the roster, and have each node apply it."""
    from .bootstrap_config import load_operational_config
    from .install import _election_context
    from .inventory import collect_inventory
    from .k3s_cluster import _run_ssh_command, _ssh_target
    from .lan_election import resolve_lan_leadership
    from .nodes import identify_local_node, init_server_node, parse_nodes

    report: dict[str, Any] = {"status": "OK", "actions": []}
    inventory = collect_inventory()
    config = load_operational_config(config_path, inventory=inventory)
    effective, election = resolve_lan_leadership(config, inventory)
    nodes = parse_nodes(effective)
    init = init_server_node(nodes)
    if init is None:
        return {"status": "ERROR", "message": "no init-server node in config"}, 1

    members, init_name = mesh_members(effective)
    local_node = identify_local_node(nodes, inventory, effective)
    election_lan_ips, election_leader = _election_context(election)
    route_v4, route_v6 = _routes(effective)
    interface, port = _wg_settings(effective)
    styx = "python3 -m styxctl.cli"

    def ssh(node):
        return _ssh_target(
            node, None, effective, inventory=inventory, local_node=local_node,
            election_lan_ips=election_lan_ips, election_leader=election_leader,
        )

    # 1. Collect each node's public key.
    pubkeys: dict[str, str] = {}
    for node in nodes:
        conn = ssh(node)
        ok, detail = _run_ssh_command(
            conn.target, f"{styx} mesh pubkey-local --interface {interface}", port=conn.port, jump=conn.jump
        )
        key = detail.strip().splitlines()[-1].strip() if ok and detail.strip() else ""
        if not ok or len(key) < 40 or " " in key:
            report["status"] = "ERROR"
            report["message"] = f"could not collect public key from {node.name}: {detail}"
            return report, 1
        pubkeys[node.name] = key
        report["actions"].append(f"pubkey {node.name}: {key[:12]}…")

    for member in members:
        member.public_key = pubkeys.get(member.name)

    # 1b. pistyx PoP: ensure the SHARED pistyx key locally + pre-stage it on every node, so any node
    # can run the PoP after a DuckDNS repoint. The PoP itself is brought up on the leader (the
    # current pistyx holder), which local-NATs client traffic out its OWN WAN — no backhaul.
    from .network_plan import cluster_stack_mode
    from .nodes import pistyx_holder

    eg_interface, eg_port, eg_mtu, eg_hostname = _egress_settings(effective)
    stack = cluster_stack_mode(effective)
    holder_node = pistyx_holder(effective, nodes)
    holder_name = holder_node.name if holder_node else None
    holder_scope = _site_scope_for_node(nodes, holder_node)
    clients = pistyx_clients(effective, site_index=int(holder_scope["site_index"]))
    site_entrypoints = {
        block["entrypoint"]
        for block in _site_overlay_blocks(
            nodes,
            pubkeys=pubkeys,
            stack_mode=stack,
            election_leader=election_leader,
        )
    }

    pk_ok, pistyx_pub = ensure_pistyx_identity()
    if not pk_ok:
        report["status"] = "ERROR"
        report["message"] = f"could not prepare the pistyx key: {pistyx_pub}"
        return report, 1
    pistyx_b64 = base64.b64encode((_read_key_file(_PISTYX_KEY_PATH) or "").encode()).decode()

    for node in nodes:
        conn = ssh(node)
        sk_ok, sk_detail = _run_ssh_command(
            conn.target, f"{styx} mesh stage-pistyx-key --key-b64 {pistyx_b64}", port=conn.port, jump=conn.jump
        )
        if not sk_ok:
            report["status"] = "ERROR"
            report["message"] = f"could not stage the pistyx key on {node.name}: {sk_detail}"
            return report, 1

    def pistyx_pop_block_for(node) -> dict[str, Any] | None:
        if holder_name is None or node.name != holder_name:
            return None  # only the leader runs the PoP
        return {
            "is_leader": True,
            "interface": eg_interface,
            "port": eg_port,
            "mtu": eg_mtu,
            "stack_mode": stack,
            "gateway_v4": holder_scope["gateway_v4"],
            "gateway_v6": holder_scope["gateway_v6"],
            "network_v4": holder_scope["network_v4"],
            "network_v6": holder_scope["network_v6"],
            "clients": clients,
        }

    # 2. Push a per-node roster and apply it. Apply the leader first so its PoP is up to receive clients.
    apply_order = sorted(nodes, key=lambda n: (n.name != holder_name, n.name))
    for node in apply_order:
        hub_host = _hub_endpoint(
            init, node, election_lan_ips=election_lan_ips, inventory=inventory, local_node=local_node
        )
        roster_members = [
            {**asdict(m), "endpoint": (hub_host if m.name == init_name else None)} for m in members
        ]
        site_overlays = _site_overlay_blocks(
            nodes,
            pubkeys=pubkeys,
            stack_mode=stack,
            dialer=node,
            election_lan_ips=election_lan_ips,
            election_leader=election_leader,
            inventory=inventory,
            local_node=local_node,
        )
        roster = {
            "members": roster_members,
            "init_name": init_name,
            "route_v4": route_v4,
            "route_v6": route_v6,
            "interface": interface,
            "port": port,
            "site_overlays": site_overlays,
            "pistyx_interface": eg_interface,
            "pistyx_pop": pistyx_pop_block_for(node),
        }
        b64 = base64.b64encode(json.dumps(roster).encode()).decode()
        conn = ssh(node)
        ok, detail = _run_ssh_command(
            conn.target,
            f"{styx} mesh apply-local --roster-b64 {b64} --local-name {node.name}",
            port=conn.port, jump=conn.jump,
        )
        report["actions"].append(f"apply {node.name}: {'ok' if ok else detail}")
        if not ok:
            report["status"] = "ERROR"
            report["message"] = f"mesh apply-local failed on {node.name}: {detail}"
            return report, 1

    # 3. Enable forwarding anywhere traffic is routed between peers.
    fwd = "sudo sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1"
    forward_names = {init.name, *site_entrypoints}
    for node in sorted((n for n in nodes if n.name in forward_names), key=lambda item: item.name):
        conn = ssh(node)
        ok, detail = _run_ssh_command(conn.target, fwd, port=conn.port, jump=conn.jump)
        label = "hub/site" if node.name == init.name and node.name in site_entrypoints else (
            "hub" if node.name == init.name else "site"
        )
        report["actions"].append(f"{label} ip_forward {node.name}: {'ok' if ok else detail}")

    report["hub"] = init_name
    report["spokes"] = [m.name for m in members if m.name != init_name]
    report["pistyx"] = holder_name
    report["pistyx_site_index"] = holder_scope["site_index"]
    report["message"] = (
        f"Styx mesh up: hub {init_name}, {len(members) - 1} spoke(s); pistyx egress on {holder_name}"
    )
    return report, 0


def render_mesh_report_text(report: dict[str, Any]) -> str:
    lines = [f"=== styx mesh — {report.get('status', 'OK')} ==="]
    if report.get("message"):
        lines.append(report["message"])
    if report.get("hub"):
        lines.append(f"hub: {report['hub']}")
    if report.get("spokes"):
        lines.append(f"spokes: {', '.join(report['spokes'])}")
    if report.get("route"):
        lines.append(f"spoke route (AllowedIPs): {', '.join(report['route'])}")
    if report.get("site_overlays"):
        rendered = [
            f"{item['interface']}=site {item['site_index']} via {item['entrypoint']}:{item['port']}"
            for item in report["site_overlays"]
        ]
        lines.append(f"site overlays: {', '.join(rendered)}")
    if report.get("pistyx"):
        site = report.get("pistyx_site_index")
        site_suffix = f", site {site}" if site is not None else ""
        lines.append(
            f"pistyx (egress gateway): {report['pistyx']}  "
            f"[interface {report.get('egress_interface', 'StyxEgress')}{site_suffix}]"
        )
    for action in report.get("actions", []):
        lines.append(f"  - {action}")
    for name, cfg in (report.get("configs") or {}).items():
        lines.append("")
        lines.append(f"--- {name} [mesh] ---")
        lines.append(cfg.rstrip())
    for name, configs in (report.get("site_configs") or {}).items():
        for interface, cfg in configs.items():
            lines.append("")
            lines.append(f"--- {name} [{interface}] ---")
            lines.append(cfg.rstrip())
    for name, cfg in (report.get("egress_configs") or {}).items():
        lines.append("")
        lines.append(f"--- {name} [StyxEgress] ---")
        lines.append(cfg.rstrip())
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- egress / client


def _egress_settings(config: dict[str, Any]) -> tuple[str, int, int, str]:
    """Return (interface, port, mtu, hostname) for the movable-pistyx StyxEgress interface."""
    eg = config.get("egress", {})
    if not isinstance(eg, dict):
        eg = {}
    interface = eg.get("interface", "StyxEgress")
    port = eg.get("port", 47801)
    mtu = eg.get("mtu", 1420)
    hostname = eg.get("hostname", "pistyx.duckdns.org")
    return (
        interface if isinstance(interface, str) else "StyxEgress",
        port if isinstance(port, int) else 47801,
        mtu if isinstance(mtu, int) else 1420,
        hostname if isinstance(hostname, str) else "pistyx.duckdns.org",
    )


# Two private keys live on each node for the egress overlay:
#   - the STABLE pistyx key (same on every node, pre-staged) — used when this node IS the holder;
#   - this node's OWN egress key (unique, stable) — used when this node is a spoke.
# The active StyxEgress.conf is re-rendered each apply with whichever key the current role needs.
_PISTYX_KEY_PATH = Path("/etc/wireguard/pistyx.key")


def _read_key_file(path: Path) -> str | None:
    try:
        out = subprocess.run(
            ["sudo", "cat", str(path)], check=False, capture_output=True, text=True, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return out.strip() or None


def _write_key_file(path: Path, key: str) -> RunResult:
    from .remediation import _run_mutating

    tmp = Path("/tmp") / f"styx-{path.name}"
    try:
        tmp.write_text(key.strip() + "\n", encoding="utf-8")
    except OSError as exc:
        return False, str(exc)
    for cmd in (["mkdir", "-p", "/etc/wireguard"], ["cp", str(tmp), str(path)], ["chmod", "600", str(path)]):
        ok, detail = _run_mutating(cmd, use_sudo=True, sudo_available=True)
        if not ok:
            return False, detail
    tmp.unlink(missing_ok=True)
    return True, f"wrote {path}"


def ensure_pistyx_identity() -> tuple[bool, str]:
    """Ensure the STABLE pistyx private key is on local disk (generate if absent); return (ok, pubkey).

    Pre-staged on every node so any node can become the holder without a runtime fetch — the key
    must be local BEFORE StyxEgress comes up (MooseFS isn't mounted that early).
    """
    private = _read_key_file(_PISTYX_KEY_PATH)
    if private is None:
        private = _gen_private_key()
        if private is None:
            return False, "wg not available to generate the pistyx key"
        ok, detail = _write_key_file(_PISTYX_KEY_PATH, private)
        if not ok:
            return False, detail
    public = _public_key(private)
    if public is None:
        return False, "could not derive pistyx public key (is wireguard-tools installed?)"
    return True, public


def stage_pistyx_key(key_b64: str) -> tuple[bool, str]:
    """Write a pushed STABLE pistyx private key to local disk (called over SSH by `mesh up`)."""
    try:
        key = base64.b64decode(key_b64).decode().strip()
    except (ValueError, UnicodeDecodeError) as exc:
        return False, f"bad key payload: {exc}"
    if not key or " " in key:
        return False, "invalid pistyx key payload"
    return _write_key_file(_PISTYX_KEY_PATH, key)


def _detect_wan_interface() -> str | None:
    """Interface holding the default route (the real WAN egress); never hardcoded."""
    try:
        out = subprocess.run(
            ["bash", "-c", "ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \\K\\S+' | head -n1"],
            check=False, capture_output=True, text=True, timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return out or None


def ensure_egress_nat(
    stack_mode: str = "dual-stack",
    *,
    source_v4: str = "10.0.250.0/24",
    source_v6: str = "fd00:cafe:0:250::/64",
) -> tuple[bool, str]:
    """On a pistyx leader: persist forwarding + idempotent v4/v6 MASQUERADE of the client band out
    the leader's OWN WAN. Scope is the holder site's client band; styx never backhauls, so each
    site egresses its own clients locally.
    """
    from .remediation import _run_mutating

    wan = _detect_wan_interface()
    if not wan:
        return False, "could not detect WAN interface for masquerade"

    tmp = Path("/tmp/styx-egress-forward.conf")
    try:
        tmp.write_text("net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n", encoding="utf-8")
    except OSError as exc:
        return False, str(exc)
    for cmd in (
        ["cp", str(tmp), "/etc/sysctl.d/99-styx-egress.conf"],
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
    ):
        ok, detail = _run_mutating(cmd, use_sudo=True, sudo_available=True)
        if not ok:
            return False, f"forwarding: {detail}"
    tmp.unlink(missing_ok=True)

    rules = []
    if stack_mode in {"dual-stack", "ipv4-only"}:
        rules.append(("iptables", source_v4))
    if stack_mode in {"dual-stack", "ipv6-only"}:
        rules.append(("ip6tables", source_v6))
    actions = [f"wan={wan}"]
    for tool, src in rules:
        check = f"{tool} -t nat -C POSTROUTING -s {src} -o {wan} -j MASQUERADE"
        add = f"{tool} -t nat -A POSTROUTING -s {src} -o {wan} -j MASQUERADE"
        ok, detail = _run_mutating(["bash", "-c", f"{check} 2>/dev/null || {add}"], use_sudo=True, sudo_available=True)
        actions.append(f"{tool} masquerade {src}: {'ok' if ok else detail}")
        if not ok:
            return False, "; ".join(actions)
    return True, "; ".join(actions)


def apply_pistyx_pop(pop: dict[str, Any]) -> RunResult:
    """Bring up THIS leader's pistyx PoP: the SHARED pistyx identity + client peers + local breakout.

    Safe by construction: the PoP interface owns only the holder site's client band and
    installs NO default route of its own, so bringing it up never disturbs the leader's own
    connectivity. Clients full-tunnel here; the leader local-NATs the client band out its OWN WAN
    (ensure_egress_nat). Brought up with `wg-quick` (never syncconf) so routes/Address install.
    """
    from .remediation import _run_mutating

    interface = pop.get("interface", "StyxEgress")
    port = int(pop.get("port", 47801))
    mtu = int(pop.get("mtu", 1420))
    stack_mode = pop.get("stack_mode", "dual-stack")

    ok, detail = ensure_pistyx_identity()
    if not ok:
        return False, f"pistyx identity: {detail}"
    private = _read_key_file(_PISTYX_KEY_PATH)
    if private is None:
        return False, "no pistyx key on disk (stage it first)"

    content = render_pistyx_pop(
        private, pop.get("clients", []),
        listen_port=port, mtu=mtu,
        gateway_v4=pop.get("gateway_v4"), gateway_v6=pop.get("gateway_v6"), stack_mode=stack_mode,
    )
    ok, detail = _write_conf(interface, content)
    if not ok:
        return False, detail
    nat_ok, nat_detail = ensure_egress_nat(
        stack_mode,
        source_v4=str(pop.get("network_v4", "10.0.250.0/24")),
        source_v6=str(pop.get("network_v6", "fd00:cafe:0:250::/64")),
    )
    if not nat_ok:
        return False, f"local breakout NAT: {nat_detail}"
    up_ok, up_detail = _run_mutating(
        ["bash", "-c", f"wg-quick down {interface} 2>/dev/null; wg-quick up {interface}"],
        use_sudo=True, sudo_available=True,
    )
    return up_ok, f"pistyx PoP up: {up_detail}" if up_ok else f"pistyx PoP up failed: {up_detail}"


def render_client_config(
    client_name: str,
    client_private_key: str,
    *,
    pistyx_pubkey: str,
    endpoint: str,
    port: int,
    address_v4: str | None,
    address_v6: str | None,
    mtu: int,
) -> str:
    """Render a client config: one [Peer] = pistyx (the SHARED entry identity), full-tunnel.

    The client dials `endpoint` — `pistyx.duckdns.org` for auto-fastest, or a specific site's name to
    pin it — and routes EVERYTHING (0.0.0.0/0, ::/0) there. Whichever leader the name resolves to
    accepts it (shared identity) and breaks its traffic out LOCALLY. A pistyx repoint reconnects the
    client transparently — no client reconfig. Families pruned to the issued address.
    """
    addr: list[str] = []
    allowed: list[str] = []
    if address_v4:
        addr.append(f"{address_v4}/32")
        allowed.append("0.0.0.0/0")
    if address_v6:
        addr.append(f"{address_v6}/128")
        allowed.append("::/0")

    lines = [
        f"# styx client: {client_name} -> {endpoint} (pistyx)",
        "[Interface]",
        f"PrivateKey = {client_private_key}",
    ]
    if addr:
        lines.append(f"Address = {', '.join(addr)}")
    lines.append(f"MTU = {mtu}")
    lines.append("")
    lines += [
        "[Peer]",
        "# pistyx (floating entry — routed to whichever site is fastest)",
        f"PublicKey = {pistyx_pubkey}",
        f"Endpoint = {endpoint}:{port}",
        f"AllowedIPs = {', '.join(allowed)}",
        f"PersistentKeepalive = {KEEPALIVE_SECONDS}",
        "",
    ]
    return "\n".join(lines) + "\n"


def _host_suffix_from_client(item: dict[str, Any], fallback_index: int) -> int:
    raw_suffix = item.get("host_suffix")
    if isinstance(raw_suffix, int) and 1 <= raw_suffix <= 254:
        return raw_suffix
    raw_slot = item.get("slot")
    if isinstance(raw_slot, int) and raw_slot >= 0:
        from .network_plan import SITE_CLIENT_OFFSET

        return SITE_CLIENT_OFFSET + raw_slot
    raw_ipv4 = item.get("ipv4")
    if isinstance(raw_ipv4, str):
        try:
            suffix = int(raw_ipv4.strip().split(".")[-1])
        except (ValueError, IndexError):
            suffix = 0
        if 1 <= suffix <= 254:
            return suffix
    from .network_plan import SITE_CLIENT_OFFSET

    return SITE_CLIENT_OFFSET + fallback_index


def pistyx_clients(config: dict[str, Any], *, site_index: int | None = None) -> list[dict[str, Any]]:
    """Parse the optional `clients:` block - clients registered as peers on every leader's PoP."""
    raw = config.get("clients")
    clients: list[dict[str, Any]] = []
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            pub = item.get("public_key")
            if not isinstance(name, str) or not isinstance(pub, str) or not pub.strip():
                continue
            host_suffix = _host_suffix_from_client(item, len(clients))
            ipv4 = item.get("ipv4")
            ipv6 = item.get("ipv6")
            if site_index is not None:
                from .network_plan import site_ipv4_for_host, site_ipv6_for_host

                ipv4 = site_ipv4_for_host(site_index, host_suffix)
                ipv6 = site_ipv6_for_host(site_index, host_suffix)
            clients.append(
                {
                    "name": name,
                    "public_key": pub.strip(),
                    "host_suffix": host_suffix,
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                }
            )
    return clients


def _endpoint_host(endpoint: str) -> str | None:
    endpoint = endpoint.strip()
    if not endpoint or endpoint == "(none)":
        return None
    if endpoint.startswith("["):
        end = endpoint.find("]")
        return endpoint[1:end] if end > 1 else None
    if ":" not in endpoint:
        return endpoint
    return endpoint.rsplit(":", 1)[0] or None


def active_pistyx_clients_from_dump(
    dump: str,
    registered_clients: list[dict[str, Any]],
    *,
    now: int | None = None,
    active_within: int = 180,
) -> list[dict[str, Any]]:
    """Parse ``wg show StyxEgress dump`` and return recently handshaken registered clients.

    The current holder learns the client's public endpoint only after the first WireGuard
    handshake. That endpoint IP is what every site leader probes during negotiation.
    """
    by_key = {
        str(client.get("public_key", "")).strip(): client
        for client in registered_clients
        if str(client.get("public_key", "")).strip()
    }
    now = int(time.time()) if now is None else now
    active: list[dict[str, Any]] = []
    for raw in dump.splitlines():
        fields = raw.rstrip("\n").split("\t")
        if len(fields) < 8:
            continue
        public_key = fields[0].strip()
        client = by_key.get(public_key)
        if client is None:
            continue
        endpoint = fields[2].strip()
        endpoint_ip = _endpoint_host(endpoint)
        if endpoint_ip is None:
            continue
        try:
            latest = int(fields[4])
        except (TypeError, ValueError):
            continue
        if latest <= 0:
            continue
        if active_within > 0 and now - latest > active_within:
            continue
        active.append(
            {
                "name": client.get("name") or public_key[:12],
                "public_key": public_key,
                "host_suffix": client.get("host_suffix"),
                "endpoint": endpoint,
                "endpoint_ip": endpoint_ip,
                "latest_handshake": latest,
                "seconds_since_handshake": max(0, now - latest),
            }
        )
    return sorted(active, key=lambda item: (str(item["name"]), str(item["public_key"])))


def _pistyx_pubkey(config: dict[str, Any]) -> str | None:
    """The SHARED pistyx public key from the `pistyx:` block (operator records it after `mesh up`)."""
    pistyx = config.get("pistyx")
    if isinstance(pistyx, dict):
        pub = pistyx.get("public_key")
        if isinstance(pub, str) and pub.strip():
            return pub.strip()
    return None


def client_config(
    name: str,
    config_path: str | Path | None = None,
    *,
    site: str | None = None,
    index: int | None = None,
    render_only: bool = False,
    register: bool = False,
) -> tuple[dict[str, Any], int]:
    """Generate a client config that dials pistyx (auto-fastest) or a pinned `site`.

    The client peers the SHARED pistyx identity; whichever leader the name resolves to accepts it and
    breaks out locally. With ``register=True`` the client is also persisted into styx.yaml's
    ``clients:`` block so the next ``mesh up`` renders it onto every leader's PoP automatically.
    """
    from .config import find_config, load_config, resolve_config
    from .client_registry import register_client, validate_client_suffix
    from .network_plan import SITE_CLIENT_OFFSET, cluster_stack_mode, site_ipv4_for_host, site_ipv6_for_host
    from .nodes import parse_nodes, pistyx_holder

    candidate = Path(config_path) if config_path is not None else find_config()
    if candidate is None:
        return {"status": "ERROR", "message": "no styx.yaml found"}, 1
    config = resolve_config(load_config(candidate))
    _eg_iface, eg_port, mtu, eg_hostname = _egress_settings(config)
    nodes = parse_nodes(config)

    endpoint = eg_hostname
    target_node = pistyx_holder(config, nodes)
    if site:
        node = next((n for n in nodes if n.name == site), None)
        if node is None or not (node.hostname or node.public_ipv4):
            return {"status": "ERROR", "message": f"site {site!r} not found or has no DuckDNS hostname"}, 1
        endpoint = node.hostname or node.public_ipv4
        target_node = node
    target_site_index = _site_index_for_node(nodes, target_node)

    stack_mode = cluster_stack_mode(config)
    want_v4 = stack_mode in {"dual-stack", "ipv4-only"}
    want_v6 = stack_mode in {"dual-stack", "ipv6-only"}
    if render_only and register:
        return {"status": "ERROR", "message": "--register cannot be combined with --render-only"}, 1
    if index is not None and index < 0:
        return {"status": "ERROR", "message": "--index must be zero or greater"}, 1
    requested_suffix: int | None = None
    if index is not None:
        requested_suffix = SITE_CLIENT_OFFSET + index
        try:
            validate_client_suffix(requested_suffix)
        except ValueError as exc:
            return {"status": "ERROR", "message": str(exc)}, 1
    elif not register:
        requested_suffix = SITE_CLIENT_OFFSET

    report: dict[str, Any] = {"status": "OK", "actions": []}
    registered: dict[str, Any] | None = None
    client_public = ""
    if render_only:
        client_private = "<client-private-key>"
        pistyx_pubkey = "<pistyx-public-key>"
        client_suffix = requested_suffix if requested_suffix is not None else SITE_CLIENT_OFFSET
        report["actions"].append("render-only: placeholder keys")
    else:
        client_private = _gen_private_key()
        if client_private is None:
            return {"status": "ERROR", "message": "wg not available to generate the client keypair"}, 1
        pistyx_pubkey = _pistyx_pubkey(config)
        if not pistyx_pubkey:
            return {
                "status": "ERROR",
                "message": "no pistyx public key — set pistyx.public_key in styx.yaml "
                "(`styxctl mesh pistyx pubkey-local` on a node prints it) before issuing clients",
            }, 1
        client_public = _public_key(client_private) or ""
        if not client_public:
            return {"status": "ERROR", "message": "wg not available to derive the client public key"}, 1
        if register:
            registered, reg_code = register_client(
                name, client_public, config_path=candidate, suffix=requested_suffix
            )
            if reg_code != 0:
                return registered, reg_code
            client_suffix = int(registered["host_suffix"])
        else:
            client_suffix = requested_suffix if requested_suffix is not None else SITE_CLIENT_OFFSET

    address_v4 = site_ipv4_for_host(target_site_index, client_suffix) if want_v4 else None
    address_v6 = site_ipv6_for_host(target_site_index, client_suffix) if want_v6 else None

    content = render_client_config(
        name, client_private,
        pistyx_pubkey=pistyx_pubkey, endpoint=endpoint, port=eg_port,
        address_v4=address_v4, address_v6=address_v6, mtu=mtu,
    )
    report["client"] = name
    report["site_index"] = target_site_index
    report["host_suffix"] = client_suffix
    report["config"] = content
    target = f"pinned site {site}" if site else "pistyx (auto-fastest)"
    report["message"] = f"client {name}: dials {endpoint}:{eg_port} via {target}"
    if not render_only:
        report["public_key"] = client_public
        report["actions"].append(
            f"client public key: {report['public_key']}"
        )
        if registered:
            report["registered"] = registered
            report["actions"].append(registered["message"])
        else:
            report["actions"].append(
                "to register automatically: re-run with `--register`; then run `styxctl mesh up` "
                "to render it onto every leader's PoP"
            )
    return report, 0


def pistyx_info(config_path: str | Path | None = None) -> tuple[dict[str, Any], int]:
    """Render-only: the current pistyx holder, reserved overlay IP, and egress settings."""
    from .config import find_config, load_config, resolve_config
    from .nodes import parse_nodes, pistyx_holder

    candidate = Path(config_path) if config_path is not None else find_config()
    if candidate is None:
        return {"status": "ERROR", "message": "no styx.yaml found"}, 1
    config = resolve_config(load_config(candidate))
    nodes = parse_nodes(config)
    holder = pistyx_holder(config, nodes)
    interface, port, mtu, hostname = _egress_settings(config)
    holder_name = holder.name if holder else "<none>"
    holder_scope = _site_scope_for_node(nodes, holder)
    report = {
        "status": "OK",
        "message": f"pistyx egress: holder {holder_name} via {hostname}:{port}",
        "actions": [
            f"interface: {interface} (separate from the mesh; wg-quick up, not syncconf)",
            f"endpoint:  {hostname}:{port}",
            f"site:      {holder_scope['site_index']} (third octet / IPv6 site segment)",
            f"overlay:   {holder_scope['gateway_v4']}/32, {holder_scope['gateway_v6']}/128 (site-scoped)",
            f"mtu:       {mtu}",
            f"holder:    {holder_name}  (to move: set pistyx.current_host, re-run `mesh up` + `deploy dns`; or `styxctl mesh pistyx probe <client-ip>` to pick the fastest site)",
        ],
    }
    return report, 0


def pistyx_probe(client_ip: str, *, config_path: str | Path | None = None) -> tuple[dict[str, Any], int]:
    """RTT-probe a client's IP from every site's leader and recommend the fastest pistyx holder.

    This is the decision half of the fastest-site loop: a client's public IP is pinged from
    each site's entrypoint over the backbone; the lowest-latency site should hold pistyx. The
    ranking/selection math is pure (:mod:`pistyx_select`, unit-tested with hysteresis so a
    marginal win never flaps the DuckDNS record). LIVE (SSH) — meaningful only with >=2 sites
    online. Applying the move stays the existing repoint: set ``pistyx.current_host`` →
    ``styxctl mesh up`` → ``styxctl deploy dns apply`` (styx-reresolve makes peers follow it).
    """
    from .bootstrap_config import load_operational_config
    from .install import _election_context
    from .inventory import collect_inventory
    from .k3s_cluster import _run_ssh_command, _ssh_target
    from .lan_election import resolve_lan_leadership
    from .nodes import identify_local_node, parse_nodes, pistyx_holder
    from .pistyx_select import parse_ping_rtt, rank_sites_by_rtt, select_fastest_site

    if not isinstance(client_ip, str) or not client_ip.strip():
        return {"status": "ERROR", "message": "a client IP (the client's public address) is required"}, 1
    client_ip = client_ip.strip()

    inventory = collect_inventory()
    config = load_operational_config(config_path, inventory=inventory)
    effective, election = resolve_lan_leadership(config, inventory)
    nodes = parse_nodes(effective)
    if not nodes:
        return {"status": "ERROR", "message": "no nodes in config"}, 1
    local_node = identify_local_node(nodes, inventory, effective)
    election_lan_ips, election_leader = _election_context(election)

    holder = pistyx_holder(effective, nodes)
    current_site = _site_index_for_node(nodes, holder) if holder else None

    samples: dict[int, float | None] = {}
    leaders: dict[int, Any] = {}
    report: dict[str, Any] = {"status": "OK", "client_ip": client_ip, "sites": []}
    for site_index in _site_indexes_for_nodes(nodes):
        leader = _site_entrypoint_for_index(nodes, site_index, election_leader=election_leader)
        leaders[site_index] = leader
        if leader is None:
            samples[site_index] = None
            report["sites"].append({"site": site_index, "leader": None, "rtt_ms": None})
            continue
        conn = _ssh_target(
            leader, None, effective, inventory=inventory, local_node=local_node,
            election_lan_ips=election_lan_ips, election_leader=election_leader,
        )
        ok, detail = _run_ssh_command(
            conn.target, f"ping -c 3 -w 5 {client_ip}", port=conn.port, jump=conn.jump
        )
        rtt = parse_ping_rtt(detail) if ok else None
        samples[site_index] = rtt
        report["sites"].append({"site": site_index, "leader": leader.name, "rtt_ms": rtt})

    target_site = select_fastest_site(samples, current_site=current_site)
    report["ranked"] = rank_sites_by_rtt(samples)
    report["current_site"] = current_site
    report["current_holder"] = holder.name if holder else None
    report["recommended_site"] = target_site
    target_leader = leaders.get(target_site) if target_site is not None else None
    report["recommended_holder"] = target_leader.name if target_leader else None

    if target_site is None:
        report["status"] = "ERROR"
        report["message"] = f"no site could reach {client_ip} — cannot recommend a pistyx holder"
        return report, 1
    if holder is not None and target_leader is not None and target_leader.name == holder.name:
        report["message"] = f"pistyx stays on {holder.name} (site {target_site}) — already the fastest reachable site"
    else:
        report["message"] = (
            f"pistyx should move to {report['recommended_holder']} (site {target_site}); to apply: set "
            f"`pistyx.current_host: {report['recommended_holder']}` in styx.yaml, then "
            "`styxctl mesh up` && `styxctl deploy dns apply`"
        )
    return report, 0


def pistyx_negotiate(
    *,
    config_path: str | Path | None = None,
    apply: bool = False,
    active_within: int = 180,
    hysteresis_ms: float | None = None,
) -> tuple[dict[str, Any], int]:
    """Negotiate the best pistyx holder for currently connected clients.

    The current holder discovers connected clients from ``wg show StyxEgress dump``. Every site
    leader probes each active client's public endpoint IP. The consensus selector picks the holder
    for the single floating ``pistyx`` DNS name. With ``apply=True``, this writes
    ``pistyx.current_host``, runs ``mesh up``, and republishes DuckDNS.
    """
    from .bootstrap_config import load_operational_config
    from .config import find_config
    from .install import _election_context
    from .inventory import collect_inventory
    from .k3s_cluster import _run_ssh_command, _ssh_target
    from .lan_election import resolve_lan_leadership
    from .nodes import identify_local_node, parse_nodes, pistyx_holder
    from .pistyx_repoint import write_pistyx_current_host
    from .pistyx_select import rank_sites_by_consensus, select_consensus_site, parse_ping_rtt

    candidate = Path(config_path) if config_path is not None else find_config()
    if candidate is None:
        return {"status": "ERROR", "message": "no styx.yaml found"}, 1

    inventory = collect_inventory()
    config = load_operational_config(candidate, inventory=inventory)
    effective, election = resolve_lan_leadership(config, inventory)
    nodes = parse_nodes(effective)
    if not nodes:
        return {"status": "ERROR", "message": "no nodes in config"}, 1
    local_node = identify_local_node(nodes, inventory, effective)
    election_lan_ips, election_leader = _election_context(election)

    holder = pistyx_holder(effective, nodes)
    if holder is None:
        return {"status": "ERROR", "message": "no pistyx holder found"}, 1
    current_site = _site_index_for_node(nodes, holder)
    eg_interface, _eg_port, _eg_mtu, _eg_hostname = _egress_settings(effective)

    registered = pistyx_clients(effective)
    report: dict[str, Any] = {
        "status": "OK",
        "mode": "apply" if apply else "plan",
        "current_holder": holder.name,
        "current_site": current_site,
        "active_within": active_within,
        "actions": [],
    }
    if not registered:
        report["message"] = "no registered clients in styx.yaml; nothing to negotiate"
        return report, 0

    conn = _ssh_target(
        holder, None, effective, inventory=inventory, local_node=local_node,
        election_lan_ips=election_lan_ips, election_leader=election_leader,
    )
    ok, detail = _run_ssh_command(
        conn.target, f"sudo wg show {shlex.quote(eg_interface)} dump 2>/dev/null",
        port=conn.port, jump=conn.jump,
    )
    if not ok:
        return {"status": "ERROR", "message": f"could not read active clients from {holder.name}: {detail}"}, 1

    active = active_pistyx_clients_from_dump(detail, registered, active_within=active_within)
    report["active_clients"] = active
    if not active:
        report["message"] = f"no clients handshook with {eg_interface} in the last {active_within}s"
        return report, 0

    leaders: dict[int, Any] = {}
    client_samples: dict[str, dict[int, float | None]] = {}
    client_reports: list[dict[str, Any]] = []
    for client in active:
        samples: dict[int, float | None] = {}
        site_rows: list[dict[str, Any]] = []
        endpoint_ip = str(client["endpoint_ip"])
        for site_index in _site_indexes_for_nodes(nodes):
            leader = _site_entrypoint_for_index(nodes, site_index, election_leader=election_leader)
            leaders[site_index] = leader
            if leader is None:
                samples[site_index] = None
                site_rows.append({"site": site_index, "leader": None, "rtt_ms": None})
                continue
            leader_conn = _ssh_target(
                leader, None, effective, inventory=inventory, local_node=local_node,
                election_lan_ips=election_lan_ips, election_leader=election_leader,
            )
            probe_ok, probe_detail = _run_ssh_command(
                leader_conn.target,
                f"ping -c 3 -w 5 {shlex.quote(endpoint_ip)}",
                port=leader_conn.port,
                jump=leader_conn.jump,
            )
            rtt = parse_ping_rtt(probe_detail) if probe_ok else None
            samples[site_index] = rtt
            site_rows.append({"site": site_index, "leader": leader.name, "rtt_ms": rtt})
        client_key = str(client["name"])
        client_samples[client_key] = samples
        client_reports.append({**client, "sites": site_rows})

    chosen = select_consensus_site(
        client_samples,
        current_site=current_site,
        hysteresis_ms=15.0 if hysteresis_ms is None else hysteresis_ms,
    )
    ranked = rank_sites_by_consensus(client_samples)
    target_leader = leaders.get(chosen) if chosen is not None else None
    report["clients"] = client_reports
    report["consensus"] = ranked
    report["recommended_site"] = chosen
    report["recommended_holder"] = target_leader.name if target_leader else None

    if chosen is None or target_leader is None:
        report["status"] = "ERROR"
        report["message"] = "no site could reach any active client; keeping current pistyx holder"
        return report, 1
    if target_leader.name == holder.name:
        report["message"] = f"pistyx stays on {holder.name} (site {current_site})"
        return report, 0

    report["message"] = (
        f"pistyx should move from {holder.name} (site {current_site}) to "
        f"{target_leader.name} (site {chosen})"
    )
    if not apply:
        report["actions"].append(
            f"plan only: set pistyx.current_host: {target_leader.name}, then run mesh up + deploy dns apply"
        )
        return report, 0

    write_report, write_code = write_pistyx_current_host(target_leader.name, config_path=candidate)
    report["actions"].append(write_report.get("message", "updated pistyx.current_host"))
    if write_code != 0:
        report["status"] = "ERROR"
        report["message"] = write_report.get("message", "failed to update pistyx.current_host")
        return report, write_code

    mesh_report, mesh_code = mesh_up(config_path=candidate)
    report["mesh_up"] = {"status": mesh_report.get("status"), "message": mesh_report.get("message")}
    report["actions"].append(mesh_report.get("message", "mesh up completed"))
    if mesh_code != 0:
        report["status"] = "ERROR"
        report["message"] = mesh_report.get("message", "mesh up failed after pistyx repoint")
        return report, mesh_code

    from .dns_publish import deploy_dns

    dns_report, dns_code = deploy_dns(dry_run=False, config_path=candidate)
    report["deploy_dns"] = {"status": dns_report.get("status"), "message": dns_report.get("message")}
    report["actions"].append(dns_report.get("message", "deploy dns completed"))
    if dns_code != 0:
        report["status"] = "ERROR"
        report["message"] = dns_report.get("message", "deploy dns failed after pistyx repoint")
        return report, dns_code

    report["message"] = (
        f"pistyx moved to {target_leader.name} (site {chosen}); clients will follow after DNS/reresolve"
    )
    return report, 0


def render_pistyx_probe_text(report: dict[str, Any]) -> str:
    lines = [f"=== pistyx probe — {report.get('status', 'OK')} ==="]
    if report.get("client_ip"):
        lines.append(f"client: {report['client_ip']}")
    if report.get("current_holder"):
        lines.append(f"current holder: {report['current_holder']} (site {report.get('current_site')})")
    for site in report.get("sites", []):
        rtt = site.get("rtt_ms")
        rtt_text = f"{rtt:.1f} ms" if isinstance(rtt, (int, float)) else "unreachable"
        leader = site.get("leader") or "<no leader>"
        lines.append(f"  site {site.get('site')} via {leader}: {rtt_text}")
    if report.get("message"):
        lines.append(report["message"])
    return "\n".join(lines) + "\n"


def render_pistyx_negotiate_text(report: dict[str, Any]) -> str:
    mode = report.get("mode", "plan")
    lines = [f"=== pistyx negotiate ({mode}) — {report.get('status', 'OK')} ==="]
    if report.get("current_holder"):
        lines.append(f"current holder: {report['current_holder']} (site {report.get('current_site')})")
    for client in report.get("clients") or report.get("active_clients") or []:
        lines.append(
            f"client {client.get('name')}: endpoint {client.get('endpoint_ip')} "
            f"(last handshake {client.get('seconds_since_handshake')}s ago)"
        )
        for site in client.get("sites", []):
            rtt = site.get("rtt_ms")
            rtt_text = f"{rtt:.1f} ms" if isinstance(rtt, (int, float)) else "unreachable"
            leader = site.get("leader") or "<no leader>"
            lines.append(f"  site {site.get('site')} via {leader}: {rtt_text}")
    if report.get("consensus"):
        lines.append("consensus:")
        for row in report["consensus"]:
            lines.append(
                f"  site {row['site']}: {row['reachable']} client(s), avg {row['avg_rtt_ms']:.1f} ms"
            )
    if report.get("recommended_holder"):
        lines.append(
            f"recommended holder: {report['recommended_holder']} (site {report.get('recommended_site')})"
        )
    if report.get("message"):
        lines.append(str(report["message"]))
    for action in report.get("actions", []):
        lines.append(f"  - {action}")
    return "\n".join(lines) + "\n"
