"""Config loading and validation helpers for Styx."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
from typing import Any

import yaml

from .bootstrap_config import enrich_operational_config
from .gateway import DEFAULT_K3S_API_PORT, DEFAULT_SSH_PORT, parse_gateway_ports
from .inventory import SystemInventory, collect_inventory
from .network_plan import DEFAULT_NETWORK, assign_node_mesh_ips
from .nodes import identify_local_node, node_hostname, parse_nodes, validate_nodes, validate_nodes_warnings
from .ports import RESERVED_PORT_END, RESERVED_PORT_START


DEFAULT_CONFIG_FILENAMES = ("styx.yaml", "styx.yml")

DEFAULT_CONFIG: dict[str, Any] = {
    "cluster": {
        "mode": "dual-stack",
        "lan_election": {
            "port": 47802,
            "collect_sec": 3,
        },
    },
    "gateway": {
        "ssh_port": DEFAULT_SSH_PORT,
        "k3s_api_port": DEFAULT_K3S_API_PORT,
    },
    "network": dict(DEFAULT_NETWORK),
    "wireguard": {
        "interface": "Styx",
        "port": 47800,
    },
    # Movable-pistyx full-tunnel egress. Separate WG interface (brought up via wg-quick, never
    # syncconf) so the default route + anti-loop fwmark install. hostname is the movable DuckDNS
    # name; the stable pistyx private key lives on the shared keystore, never in styx.yaml.
    "egress": {
        "interface": "StyxEgress",
        "port": 47801,
        "mtu": 1420,
        "hostname": "pistyx.duckdns.org",
    },
}


class ConfigError(RuntimeError):
    """Raised when a Styx config file cannot be loaded."""


@dataclass(slots=True)
class ValidationIssue:
    level: str
    path: str
    message: str


def find_config(start: Path | None = None) -> Path | None:
    base = start or Path.cwd()
    for name in DEFAULT_CONFIG_FILENAMES:
        candidate = base / name
        if candidate.exists():
            return candidate
    return None


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def resolve_config(config: dict[str, Any]) -> dict[str, Any]:
    """Apply built-in defaults and auto-assign mesh IPs from the backbone plan."""
    if not config:
        return {}
    resolved = _deep_merge(DEFAULT_CONFIG, config)
    assign_node_mesh_ips(resolved)
    return resolved


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    candidate = Path(path) if path is not None else find_config()
    if candidate is None:
        return {}
    try:
        data = yaml.safe_load(candidate.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"Could not read config file {candidate}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Could not parse config file {candidate}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"Config file {candidate} must contain a YAML mapping at the top level")
    return resolve_config(data)


def _require_mapping(value: Any, path: str, issues: list[ValidationIssue]) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        issues.append(ValidationIssue("error", path, "expected a mapping"))
        return None
    return value


def _require_str(value: Any, path: str, issues: list[ValidationIssue]) -> str | None:
    if not isinstance(value, str) or not value.strip():
        issues.append(ValidationIssue("error", path, "expected a non-empty string"))
        return None
    return value.strip()


def _validate_network_prefix(value: Any, path: str, issues: list[ValidationIssue]) -> None:
    if not isinstance(value, str):
        issues.append(ValidationIssue("error", path, "expected a CIDR string"))
        return
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        issues.append(ValidationIssue("error", path, str(exc)))


def validate_config(
    config: dict[str, Any],
    *,
    inventory: SystemInventory | None = None,
) -> list[ValidationIssue]:
    """Validate a loaded Styx config mapping."""
    issues: list[ValidationIssue] = []

    if not config:
        issues.append(
            ValidationIssue(
                "warning",
                "config",
                "no styx.yaml found; MVP1 local commands work without config",
            )
        )
        return issues

    config = resolve_config(config)
    if inventory is not None:
        config = enrich_operational_config(config, inventory)

    local_node = None
    nodes = parse_nodes(config)
    if inventory is not None and nodes:
        local_node = identify_local_node(nodes, inventory, config)

    cluster = _require_mapping(config.get("cluster"), "cluster", issues)
    if cluster:
        _require_str(cluster.get("name"), "cluster.name", issues)
        mode = cluster.get("mode")
        if mode is not None and mode not in {"dual-stack", "ipv4-only", "ipv6-only"}:
            issues.append(
                ValidationIssue(
                    "error",
                    "cluster.mode",
                    "expected dual-stack, ipv4-only, or ipv6-only",
                )
            )
        lan_election = cluster.get("lan_election")
        if lan_election is not None:
            lan_map = _require_mapping(lan_election, "cluster.lan_election", issues)
            if lan_map:
                port = lan_map.get("port")
                if port is not None and (not isinstance(port, int) or not (1 <= port <= 65535)):
                    issues.append(
                        ValidationIssue("error", "cluster.lan_election.port", "expected integer port 1-65535")
                    )
                collect_sec = lan_map.get("collect_sec")
                if collect_sec is not None and (not isinstance(collect_sec, (int, float)) or collect_sec <= 0):
                    issues.append(
                        ValidationIssue("error", "cluster.lan_election.collect_sec", "expected positive number")
                    )

    network = config.get("network")
    if isinstance(network, dict):
        for key in (
            "ipv4_supernet",
            "ipv6_supernet",
            "mesh_ipv4",
            "infra_ipv4",
            "pod_ipv4",
            "service_ipv4",
            "mesh_ipv6",
            "infra_ipv6",
            "pod_ipv6",
            "service_ipv6",
            "roadwarrior_ipv4",
            "roadwarrior_ipv6",
            "pistyx_ipv4",
            "pistyx_ipv6",
        ):
            if key in network:
                _validate_network_prefix(network.get(key), f"network.{key}", issues)

    wireguard = config.get("wireguard")
    if isinstance(wireguard, dict):
        interface = _require_str(wireguard.get("interface"), "wireguard.interface", issues)
        if interface and interface == "wg0":
            issues.append(
                ValidationIssue(
                    "error",
                    "wireguard.interface",
                    "Styx WireGuard interface must not be wg0; wg0 is preserved on gateway nodes",
                )
            )
        port = wireguard.get("port")
        if port is None:
            issues.append(ValidationIssue("error", "wireguard.port", "expected an integer port"))
        elif not isinstance(port, int):
            issues.append(ValidationIssue("error", "wireguard.port", "expected an integer port"))
        elif not (RESERVED_PORT_START <= port <= RESERVED_PORT_END):
            issues.append(
                ValidationIssue(
                    "error",
                    "wireguard.port",
                    f"port must be within Styx reserved range {RESERVED_PORT_START}-{RESERVED_PORT_END}",
                )
            )

    egress = config.get("egress")
    if isinstance(egress, dict):
        eg_interface = _require_str(egress.get("interface"), "egress.interface", issues)
        wg_interface = wireguard.get("interface") if isinstance(wireguard, dict) else None
        if eg_interface and eg_interface == wg_interface:
            issues.append(
                ValidationIssue(
                    "error",
                    "egress.interface",
                    "egress interface must differ from the mesh wireguard interface",
                )
            )
        eg_port = egress.get("port")
        if not isinstance(eg_port, int):
            issues.append(ValidationIssue("error", "egress.port", "expected an integer port"))
        elif not (RESERVED_PORT_START <= eg_port <= RESERVED_PORT_END):
            issues.append(
                ValidationIssue(
                    "error",
                    "egress.port",
                    f"port must be within Styx reserved range {RESERVED_PORT_START}-{RESERVED_PORT_END}",
                )
            )
        elif isinstance(wireguard, dict) and eg_port == wireguard.get("port"):
            issues.append(
                ValidationIssue(
                    "error",
                    "egress.port",
                    "egress port must differ from the mesh wireguard port (the pistyx holder runs both)",
                )
            )
        mtu = egress.get("mtu")
        if mtu is not None and (not isinstance(mtu, int) or not (1280 <= mtu <= 1500)):
            issues.append(ValidationIssue("error", "egress.mtu", "expected an integer MTU 1280-1500"))
        _require_str(egress.get("hostname"), "egress.hostname", issues)

    gateway = parse_gateway_ports(config)
    for message in gateway.validate():
        issues.append(ValidationIssue("error", "gateway", message))

    siem = config.get("siem")
    if siem is not None:
        siem_map = _require_mapping(siem, "siem", issues)
        if siem_map and siem_map.get("enabled") is True:
            _require_str(siem_map.get("provider"), "siem.provider", issues)

    dns = config.get("dns")
    if dns is not None:
        dns_map = _require_mapping(dns, "dns", issues)
        if dns_map:
            # DuckDNS is the only supported provider — no provider field to validate.
            # Per-site DuckDNS names are derived from each node's `hostname` — not listed here.
            interval = dns_map.get("interval_seconds")
            if interval is not None and (not isinstance(interval, int) or interval <= 0):
                issues.append(
                    ValidationIssue("error", "dns.interval_seconds", "expected a positive integer")
                )

    nodes = parse_nodes(config)
    if nodes:
        for message in validate_nodes(
            nodes,
            config,
            inventory=inventory,
            local_node=local_node,
        ):
            issues.append(ValidationIssue("error", "nodes", message))
        for message in validate_nodes_warnings(
            nodes,
            config,
            inventory=inventory,
            local_node=local_node,
        ):
            issues.append(ValidationIssue("warning", "nodes", message))
    else:
        issues.append(
            ValidationIssue(
                "warning",
                "nodes",
                "no cluster nodes defined; install cluster requires nodes with IPs in styx.yaml",
            )
        )

    return issues


def config_status(issues: list[ValidationIssue]) -> str:
    if any(issue.level == "error" for issue in issues):
        return "INVALID"
    if issues:
        return "VALID_WITH_WARNINGS"
    return "VALID"


def format_config_summary(config: dict[str, Any], config_path: Path | None) -> str:
    lines = ["Styx Config Summary", "===================", ""]
    if config_path is None:
        lines.append("Config file: not found")
        lines.append("Using empty defaults.")
        return "\n".join(lines).rstrip() + "\n"

    config = resolve_config(config)
    lines.append(f"Config file: {config_path}")
    cluster = config.get("cluster", {})
    wireguard = config.get("wireguard", {})
    gateway = parse_gateway_ports(config)
    lines.append(f"Cluster: {cluster.get('name', 'unknown')} ({cluster.get('mode', 'unknown')})")
    lines.append(
        "WireGuard: "
        f"{wireguard.get('interface', 'unknown')} on port {wireguard.get('port', 'unknown')}"
    )
    lines.append(f"Gateway ports: SSH {gateway.ssh}, k3s API {gateway.k3s_api}")
    siem = config.get("siem", {})
    if siem:
        provider = siem.get("provider")
        provider_suffix = f" ({provider})" if provider else ""
        lines.append(f"SIEM: {'enabled' if siem.get('enabled') else 'disabled'}{provider_suffix}")
    nodes = parse_nodes(config)
    if nodes:
        lines.append(f"Nodes: {len(nodes)} configured")
        for node in nodes:
            host = node_hostname(config, node) or "-"
            pub = node.public_ipv4 or "-"
            pub6 = node.public_ipv6 or "-"
            lan = node.lan_ip or "-"
            ips = ", ".join(filter(None, (node.ipv4, node.ipv6)))
            entry = " entrypoint" if node.site_entrypoint else ""
            host_suffix = f" hostname {host}" if host != "-" else ""
            lines.append(
                f"  - {node.name} ({node.role}) public {pub} public6 {pub6} lan {lan}{host_suffix} mesh {ips}{entry}"
            )
    return "\n".join(lines).rstrip() + "\n"
