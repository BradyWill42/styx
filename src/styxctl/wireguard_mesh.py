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
    for action in report.get("actions", []):
        lines.append(f"  - {action}")
    for name, cfg in (report.get("configs") or {}).items():
        lines.append("")
        lines.append(f"--- {name} ---")
        lines.append(cfg.rstrip())
    return "\n".join(lines) + "\n"
