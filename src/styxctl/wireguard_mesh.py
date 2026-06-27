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
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

KEEPALIVE_SECONDS = 25
RunResult = tuple[bool, str]


@dataclass(slots=True)
class MeshMember:
    name: str
    role: str
    ipv4: str | None          # mesh overlay IP (10.0.0.x)
    ipv6: str | None
    public_key: str | None = None   # filled by `mesh up`; placeholder in `mesh plan`
    endpoint: str | None = None      # hub's reachable host as seen by a spoke (host only)


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


def render_egress_config(
    local_name: str,
    private_key: str,
    members: list[MeshMember],
    holder_name: str,
    *,
    listen_port: int,
    mtu: int,
    stack_mode: str = "dual-stack",
) -> str:
    """Render a node's StyxEgress interface — the movable-pistyx full-tunnel egress overlay.

    A SECOND hub-and-spoke, separate from the mesh and ALWAYS cycled with `wg-quick up/down` (never
    `wg syncconf`) so the default route + Table=auto fwmark + suppress_prefixlength loop-avoidance
    install. `members` carry each node's EGRESS overlay address (ipv4/ipv6) and egress public_key;
    the holder (pistyx) is the hub. The holder owns the egress subnet and gets one [Peer] per spoke
    (routed by the spoke's egress /32, +/128) with NO self-peer (it egresses natively, NAT out-of-band).
    A spoke gets a single [Peer] = the holder with AllowedIPs 0.0.0.0/0 + ::/0 (full tunnel).
    """
    want_v4 = stack_mode in {"dual-stack", "ipv4-only"}
    want_v6 = stack_mode in {"dual-stack", "ipv6-only"}
    by_name = {m.name: m for m in members}
    local = by_name[local_name]
    holder = by_name.get(holder_name)
    is_holder = local_name == holder_name

    lines = ["[Interface]", f"PrivateKey = {private_key}"]
    addr: list[str] = []
    if want_v4 and local.ipv4:
        addr.append(f"{local.ipv4}/24" if is_holder else f"{local.ipv4}/32")
    if want_v6 and local.ipv6:
        addr.append(f"{local.ipv6}/64" if is_holder else f"{local.ipv6}/128")
    if addr:
        lines.append(f"Address = {', '.join(addr)}")
    lines.append(f"MTU = {mtu}")
    if is_holder:
        lines.append(f"ListenPort = {listen_port}")
    lines.append("")

    if is_holder:
        for member in members:
            if member.name == holder_name:
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
                f"# {member.name}",
                f"PublicKey = {member.public_key}",
                f"AllowedIPs = {', '.join(allowed)}",
                "",
            ]
    elif holder is not None:
        allowed = []
        if want_v4:
            allowed.append("0.0.0.0/0")
        if want_v6:
            allowed.append("::/0")
        lines += ["[Peer]", "# pistyx (floating gateway)", f"PublicKey = {holder.public_key}"]
        if holder.endpoint:
            lines.append(f"Endpoint = {holder.endpoint}:{listen_port}")
        lines.append(f"AllowedIPs = {', '.join(allowed)}")
        lines.append(f"PersistentKeepalive = {KEEPALIVE_SECONDS}")
        lines.append("")
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


def egress_members(config: dict[str, Any]) -> tuple[list[MeshMember], str | None]:
    """Build StyxEgress members (egress overlay addresses + roles); return (members, holder_name).

    The holder (pistyx) takes the reserved overlay .1; every other node takes its own node-egress
    address. MeshMember.ipv4/ipv6 here are the EGRESS addresses (not the mesh addresses).
    """
    from .network_plan import (
        PISTYX_IPV4,
        PISTYX_IPV6,
        cluster_stack_mode,
        node_egress_ipv4_for_index,
        node_egress_ipv6_for_index,
    )
    from .nodes import parse_nodes, pistyx_holder

    nodes = parse_nodes(config)
    holder = pistyx_holder(config, nodes)
    holder_name = holder.name if holder else None
    mode = cluster_stack_mode(config)
    want_v4 = mode in {"dual-stack", "ipv4-only"}
    want_v6 = mode in {"dual-stack", "ipv6-only"}

    members: list[MeshMember] = []
    for index, node in enumerate(nodes):
        if node.name == holder_name:
            ev4, ev6 = PISTYX_IPV4, PISTYX_IPV6
        else:
            ev4, ev6 = node_egress_ipv4_for_index(index), node_egress_ipv6_for_index(index)
        members.append(
            MeshMember(
                name=node.name,
                role=node.role,
                ipv4=ev4 if want_v4 else None,
                ipv6=ev6 if want_v6 else None,
            )
        )
    return members, holder_name


def _wg_settings(config: dict[str, Any]) -> tuple[str, int]:
    wg = config.get("wireguard", {})
    interface = wg.get("interface", "Styx")
    port = wg.get("port", 47800)
    return (interface if isinstance(interface, str) else "Styx"), (port if isinstance(port, int) else 47800)


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
    role = "hub" if local_name == init_name else "spoke"
    report["message"] = f"{local_name} mesh config applied ({role})"
    return report, (0 if synced else 1)


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

    # Placeholder keys + a single representative hub endpoint for preview.
    for member in members:
        member.public_key = f"<pubkey:{member.name}>"
        if member.name == init_name:
            member.endpoint = init_host

    report: dict[str, Any] = {
        "status": "OK",
        "interface": interface,
        "hub": init_name,
        "spokes": [m.name for m in members if m.name != init_name],
        "route": [r for r in (route_v4, route_v6) if r],
        "configs": {
            m.name: render_local_config(
                m.name, f"<privkey:{m.name}>", members, init_name,
                listen_port=port, route_v4=route_v4, route_v6=route_v6,
            )
            for m in members
        },
    }

    # Egress overlay preview: StyxEgress -> the floating pistyx gateway (full tunnel).
    from .network_plan import cluster_stack_mode

    eg_members, holder_name = egress_members(config)
    eg_interface, eg_port, eg_mtu, eg_hostname = _egress_settings(config)
    stack = cluster_stack_mode(config)
    for member in eg_members:
        member.public_key = f"<pubkey:{member.name}-egress>"
        if member.name == holder_name:
            member.endpoint = eg_hostname   # the FLOATING name, not the holder node's hostname
    report["pistyx"] = holder_name
    report["egress_interface"] = eg_interface
    report["egress_configs"] = (
        {
            m.name: render_egress_config(
                m.name, f"<privkey:{m.name}-egress>", eg_members, holder_name,
                listen_port=eg_port, mtu=eg_mtu, stack_mode=stack,
            )
            for m in eg_members
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

    # 2. Push a per-node roster (hub endpoint computed for that node) and apply it.
    for node in nodes:
        hub_host = _hub_endpoint(
            init, node, election_lan_ips=election_lan_ips, inventory=inventory, local_node=local_node
        )
        roster_members = [
            {**asdict(m), "endpoint": (hub_host if m.name == init_name else None)} for m in members
        ]
        roster = {
            "members": roster_members,
            "init_name": init_name,
            "route_v4": route_v4,
            "route_v6": route_v6,
            "interface": interface,
            "port": port,
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

    # 3. Enable forwarding on the hub so it routes between spokes.
    conn = ssh(init)
    fwd = "sudo sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1"
    ok, detail = _run_ssh_command(conn.target, fwd, port=conn.port, jump=conn.jump)
    report["actions"].append(f"hub ip_forward: {'ok' if ok else detail}")

    report["hub"] = init_name
    report["spokes"] = [m.name for m in members if m.name != init_name]
    report["message"] = f"Styx mesh up: hub {init_name}, {len(members) - 1} spoke(s)"
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
    if report.get("pistyx"):
        lines.append(f"pistyx (egress gateway): {report['pistyx']}  [interface {report.get('egress_interface', 'StyxEgress')}]")
    for action in report.get("actions", []):
        lines.append(f"  - {action}")
    for name, cfg in (report.get("configs") or {}).items():
        lines.append("")
        lines.append(f"--- {name} [mesh] ---")
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


def render_client_config(
    client_name: str,
    client_private_key: str,
    *,
    site_pubkey: str,
    site_endpoint: str,
    site_port: int,
    address_v4: str | None,
    address_v6: str | None,
    mtu: int,
) -> str:
    """Render a roadwarrior client config: one [Peer] = the chosen ENTRY site's leader, full-tunnel.

    The client homes to the site it dials (Endpoint = that site's DuckDNS name) and routes
    EVERYTHING (0.0.0.0/0, ::/0) to that leader, which forwards to pistyx. The client never peers
    pistyx directly, so a pistyx move is invisible to it. Families are pruned to the issued address.
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
        f"# styx roadwarrior: {client_name} - entry via {site_endpoint}, egress via pistyx",
        "[Interface]",
        f"PrivateKey = {client_private_key}",
    ]
    if addr:
        lines.append(f"Address = {', '.join(addr)}")
    lines.append(f"MTU = {mtu}")
    lines.append("")
    lines += [
        "[Peer]",
        "# entry-site leader (forwards full-tunnel to pistyx)",
        f"PublicKey = {site_pubkey}",
        f"Endpoint = {site_endpoint}:{site_port}",
        f"AllowedIPs = {', '.join(allowed)}",
        f"PersistentKeepalive = {KEEPALIVE_SECONDS}",
        "",
    ]
    return "\n".join(lines) + "\n"


def _collect_site_pubkey(site_node: ClusterNode, config: dict[str, Any]) -> tuple[str | None, str]:
    """SSH the chosen entry site and read its mesh WireGuard public key (for a real client config)."""
    from .install import _election_context
    from .inventory import collect_inventory
    from .k3s_cluster import _run_ssh_command, _ssh_target
    from .lan_election import resolve_lan_leadership
    from .nodes import identify_local_node, parse_nodes

    inventory = collect_inventory()
    effective, election = resolve_lan_leadership(config, inventory)
    nodes = parse_nodes(effective)
    local_node = identify_local_node(nodes, inventory, effective)
    election_lan_ips, election_leader = _election_context(election)
    interface, _port = _wg_settings(effective)
    target = next((n for n in nodes if n.name == site_node.name), site_node)
    conn = _ssh_target(
        target, None, effective, inventory=inventory, local_node=local_node,
        election_lan_ips=election_lan_ips, election_leader=election_leader,
    )
    ok, detail = _run_ssh_command(
        conn.target, f"python3 -m styxctl.cli mesh pubkey-local --interface {interface}",
        port=conn.port, jump=conn.jump,
    )
    key = detail.strip().splitlines()[-1].strip() if ok and detail.strip() else ""
    if not ok or len(key) < 40 or " " in key:
        return None, detail.strip() or "no key returned"
    return key, "ok"


def client_config(
    site: str,
    config_path: str | Path | None = None,
    *,
    name: str | None = None,
    index: int = 0,
    render_only: bool = False,
) -> tuple[dict[str, Any], int]:
    """Generate a roadwarrior client config homing to `site` (a node name), egressing via pistyx."""
    from .config import find_config, load_config, resolve_config
    from .network_plan import cluster_stack_mode, roadwarrior_ipv4_for_index, roadwarrior_ipv6_for_index
    from .nodes import parse_nodes

    candidate = Path(config_path) if config_path is not None else find_config()
    if candidate is None:
        return {"status": "ERROR", "message": "no styx.yaml found"}, 1
    config = resolve_config(load_config(candidate))
    nodes = parse_nodes(config)
    site_node = next((n for n in nodes if n.name == site), None)
    if site_node is None:
        available = ", ".join(n.name for n in nodes) or "(none)"
        return {"status": "ERROR", "message": f"no entry site named {site!r}; sites are node names: {available}"}, 1

    site_endpoint = site_node.hostname or site_node.public_ipv4
    if not site_endpoint:
        return {"status": "ERROR", "message": f"entry site {site!r} has no DuckDNS hostname/public_ipv4 to dial"}, 1

    _iface, mesh_port = _wg_settings(config)
    _eg_iface, _eg_port, mtu, _eg_host = _egress_settings(config)
    stack_mode = cluster_stack_mode(config)
    want_v4 = stack_mode in {"dual-stack", "ipv4-only"}
    want_v6 = stack_mode in {"dual-stack", "ipv6-only"}
    address_v4 = roadwarrior_ipv4_for_index(index) if want_v4 else None
    address_v6 = roadwarrior_ipv6_for_index(index) if want_v6 else None
    client_name = name or f"{site}-client{index}"

    report: dict[str, Any] = {"status": "OK", "actions": []}
    if render_only:
        client_private = "<client-private-key>"
        site_pubkey = f"<pubkey:{site}>"
        report["actions"].append("render-only: placeholder keys (no wg/SSH)")
    else:
        client_private = _gen_private_key()
        if client_private is None:
            return {"status": "ERROR", "message": "wg not available to generate the client keypair"}, 1
        site_pubkey, detail = _collect_site_pubkey(site_node, config)
        if not site_pubkey:
            return {"status": "ERROR", "message": f"could not collect {site} public key: {detail}"}, 1

    content = render_client_config(
        client_name, client_private,
        site_pubkey=site_pubkey, site_endpoint=site_endpoint, site_port=mesh_port,
        address_v4=address_v4, address_v6=address_v6, mtu=mtu,
    )
    report["client"] = client_name
    report["config"] = content
    report["message"] = f"client {client_name}: home site {site} ({site_endpoint}), egress via pistyx"
    if not render_only:
        report["actions"].append("register this client on the entry-site leader before it can connect (Phase 2)")
    return report, 0


def pistyx_info(config_path: str | Path | None = None) -> tuple[dict[str, Any], int]:
    """Render-only: the current pistyx holder, reserved overlay IP, and egress settings."""
    from .config import find_config, load_config, resolve_config
    from .network_plan import PISTYX_IPV4, PISTYX_IPV6
    from .nodes import parse_nodes, pistyx_holder

    candidate = Path(config_path) if config_path is not None else find_config()
    if candidate is None:
        return {"status": "ERROR", "message": "no styx.yaml found"}, 1
    config = resolve_config(load_config(candidate))
    nodes = parse_nodes(config)
    holder = pistyx_holder(config, nodes)
    interface, port, mtu, hostname = _egress_settings(config)
    holder_name = holder.name if holder else "<none>"
    report = {
        "status": "OK",
        "message": f"pistyx egress: holder {holder_name} via {hostname}:{port}",
        "actions": [
            f"interface: {interface} (separate from the mesh; wg-quick up, not syncconf)",
            f"endpoint:  {hostname}:{port}",
            f"overlay:   {PISTYX_IPV4}/32, {PISTYX_IPV6}/128 (reserved)",
            f"mtu:       {mtu}",
            f"holder:    {holder_name}  (move with `styxctl mesh pistyx move <node>`, Phase 2)",
        ],
    }
    return report, 0
