"""Config loading and validation helpers for Styx."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
from typing import Any

import yaml

from .ports import RESERVED_PORT_END, RESERVED_PORT_START
from .nodes import parse_nodes, validate_nodes


DEFAULT_CONFIG_FILENAMES = ("styx.yaml", "styx.yml")


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
    return data


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


def validate_config(config: dict[str, Any]) -> list[ValidationIssue]:
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

    network = _require_mapping(config.get("network"), "network", issues)
    if network:
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
        ):
            if key in network:
                _validate_network_prefix(network.get(key), f"network.{key}", issues)

    wireguard = _require_mapping(config.get("wireguard"), "wireguard", issues)
    if wireguard:
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

    dns = config.get("dns")
    if dns is not None:
        dns_map = _require_mapping(dns, "dns", issues)
        if dns_map and dns_map.get("provider") is not None:
            _require_str(dns_map.get("provider"), "dns.provider", issues)

    siem = config.get("siem")
    if siem is not None:
        siem_map = _require_mapping(siem, "siem", issues)
        if siem_map and siem_map.get("enabled") is True:
            _require_str(siem_map.get("provider"), "siem.provider", issues)

    nodes = parse_nodes(config)
    if nodes:
        for message in validate_nodes(nodes):
            issues.append(ValidationIssue("error", "nodes", message))
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

    lines.append(f"Config file: {config_path}")
    cluster = config.get("cluster", {})
    wireguard = config.get("wireguard", {})
    lines.append(f"Cluster: {cluster.get('name', 'unknown')} ({cluster.get('mode', 'unknown')})")
    lines.append(
        "WireGuard: "
        f"{wireguard.get('interface', 'unknown')} on port {wireguard.get('port', 'unknown')}"
    )
    dns = config.get("dns", {})
    if dns:
        lines.append(f"DNS provider: {dns.get('provider', 'unknown')}")
    siem = config.get("siem", {})
    if siem:
        provider = siem.get("provider")
        provider_suffix = f" ({provider})" if provider else ""
        lines.append(f"SIEM: {'enabled' if siem.get('enabled') else 'disabled'}{provider_suffix}")
    nodes = parse_nodes(config)
    if nodes:
        lines.append(f"Nodes: {len(nodes)} configured")
        for node in nodes:
            ips = ", ".join(filter(None, (node.ipv4, node.ipv6)))
            lines.append(f"  - {node.name} ({node.role}) {ips}")
    return "\n".join(lines).rstrip() + "\n"
