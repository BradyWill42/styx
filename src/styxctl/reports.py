"""Human and JSON report generation for Styx sysprep."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from textwrap import indent
from typing import Any

from .inventory import SystemInventory
from .ports import (
    PORT_PLAN,
    RESERVED_PORT_END,
    RESERVED_PORT_START,
    PortConflict,
    conflicts_for_port,
    planned_protocol,
    port_purpose,
)


CRITICAL_PORTS = set(range(47800, 47809))


def _service_present(service: dict[str, str | None]) -> bool:
    inactive = {"missing", "inactive", "disabled", "not-found", "not found"}
    return bool({value for value in service.values() if value} - inactive)


def _artifact_warnings(inventory: SystemInventory) -> list[str]:
    return [
        f"Detected {name.replace('_', ' ')}: {', '.join(found)}"
        for name, found in inventory.detected_artifacts.items()
        if found
    ]


def evaluate_readiness(inventory: SystemInventory) -> tuple[str, list[str], list[str]]:
    """Return status, warnings, and blocking reasons."""
    warnings: list[str] = []
    blocking: list[str] = []

    for conflict in inventory.ports.conflicts:
        message = (
            f"{conflict.port}/{conflict.protocol} occupied inside Styx reserved range"
            f" by {conflict.process_name or 'unknown process'}"
            f"{f' pid {conflict.pid}' if conflict.pid else ''}"
        )
        (blocking if conflict.port in CRITICAL_PORTS else warnings).append(message)

    ports = inventory.ports
    if not ports.command_available:
        warnings.append("Could not run ss; Styx reserved port scan was not completed")
    elif ports.returncode not in (0, None):
        warnings.append("ss returned a nonzero exit code; port scan may be incomplete")
    elif ports.timed_out:
        warnings.append("ss timed out; port scan may be incomplete")

    warnings.extend(_artifact_warnings(inventory))

    if not inventory.sudo_available:
        warnings.append("Non-interactive sudo is not available for the current user")

    lowered_time = inventory.time_sync_status.lower()
    if "ntpsynchronized=no" in lowered_time or "system clock synchronized: no" in lowered_time:
        warnings.append("Time synchronization appears to be disabled or unsynchronized")

    if inventory.detected_binaries.get("k3s"):
        warnings.append(f"k3s binary detected at {inventory.detected_binaries['k3s']}")

    for key in ("k3s", "k3s_agent"):
        if _service_present(inventory.detected_services.get(key, {})):
            warnings.append(f"{key.replace('_', '-')}.service appears to exist or be active")

    if blocking:
        return "BLOCKED", warnings, blocking
    if warnings:
        return "READY_WITH_WARNINGS", warnings, blocking
    return "READY", warnings, blocking


def build_report_data(inventory: SystemInventory, command: str) -> dict[str, Any]:
    status, warnings, blocking = evaluate_readiness(inventory)
    return {
        "tool": "styxctl",
        "report_type": "sysprep",
        "command": command,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "warnings": warnings,
        "blocking": blocking,
        "inventory": inventory.to_dict(),
    }


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _present_absent(value: bool) -> str:
    return "present" if value else "absent"


def _first_line(text: str, fallback: str = "unknown") -> str:
    for line in text.splitlines():
        if stripped := line.strip():
            return stripped
    return fallback


def _block_or_none(lines: list[str], none_text: str = "none") -> str:
    if not lines:
        return f"  {none_text}"
    return "\n".join(f"  {line}" for line in lines)


def _conflict_line(conflict: PortConflict) -> str:
    owner = conflict.process_name or "unknown process"
    pid = f" pid={conflict.pid}" if conflict.pid else ""
    unit = f" unit={conflict.systemd_unit}" if conflict.systemd_unit else ""
    safe = "yes" if conflict.safe_to_stop else "no"
    extra = f" purpose={port_purpose(conflict.port)}" if conflict.port not in PORT_PLAN else ""
    return (
        f"{conflict.port}/{conflict.protocol}: occupied by {owner}{pid}{unit}{extra} "
        f"safe_to_stop={safe}"
    )


def _conflicts_from_dict(raw: list[dict[str, Any]]) -> list[PortConflict]:
    return [
        PortConflict(
            protocol=str(item.get("protocol", "")),
            port=int(item["port"]),
            process_name=item.get("process_name"),
            pid=item.get("pid"),
            systemd_unit=item.get("systemd_unit"),
            command_line=item.get("command_line"),
            safe_to_stop=bool(item.get("safe_to_stop")),
            raw=str(item.get("raw", "")),
        )
        for item in raw
    ]


def _format_detected(inv: dict[str, Any]) -> list[str]:
    interface_names = set(inv.get("interface_names", []))
    wg_interfaces = set(inv.get("wireguard_interfaces", []))
    binaries = inv.get("detected_binaries", {})
    wazuh = binaries.get("wazuh-control") or binaries.get("wazuh-agentd") or "not installed"
    wg0 = "present, preserved" if {"wg0"} & (interface_names | wg_interfaces) else "absent"
    styx = _present_absent("Styx" in interface_names or "Styx" in wg_interfaces)
    return [
        f"k3s: {binaries.get('k3s') or 'not installed'}",
        f"containerd: {binaries.get('containerd') or 'not installed'}",
        f"Docker: {binaries.get('docker') or 'not installed'}",
        f"Wazuh: {wazuh}",
        f"watchdog: {binaries.get('watchdog') or 'not installed'}",
        f"wg0: {wg0}",
        f"Styx interface: {styx}",
        f"cni0: {_present_absent('cni0' in interface_names)}",
        f"flannel.1: {_present_absent('flannel.1' in interface_names)}",
        f"flannel-v6.1: {_present_absent('flannel-v6.1' in interface_names)}",
        f"firewall backend: {inv.get('firewall_backend', {}).get('preferred', 'unknown')}",
    ]


def _format_ports(conflicts: list[PortConflict]) -> list[str]:
    lines = [f"Range: {RESERVED_PORT_START}-{RESERVED_PORT_END}"]
    for port in sorted(PORT_PLAN):
        matching = conflicts_for_port(conflicts, port)
        if matching:
            lines.extend(_conflict_line(conflict) for conflict in matching)
        else:
            lines.append(f"{port}/{planned_protocol(port)}: free ({port_purpose(port)})")

    extra = [conflict for conflict in conflicts if conflict.port not in PORT_PLAN]
    if extra:
        lines.append("Additional occupied reserved ports:")
        lines.extend(_conflict_line(conflict) for conflict in extra)
    return lines


def render_sysprep_text(report: dict[str, Any]) -> str:
    inventory = report["inventory"]
    status, warnings, blocking = report["status"], report["warnings"], report["blocking"]
    conflicts = _conflicts_from_dict(inventory.get("ports", {}).get("conflicts", []))
    artifacts = inventory.get("detected_artifacts", {})
    artifact_lines = [
        f"{name.replace('_', ' ')}: {', '.join(found) if found else 'none'}"
        for name, found in artifacts.items()
    ]
    dns_resolvers = inventory.get("dns_resolvers", [])

    text = f"""Styx Sysprep Report
====================

Node: {inventory.get('hostname', 'unknown')}
FQDN: {inventory.get('fqdn', 'unknown')}
Status: {status}
Generated: {report.get('generated_at', 'unknown')}

System:
  OS: {inventory.get('os_version', 'unknown')}
  Arch: {inventory.get('architecture', 'unknown')}
  Kernel: {inventory.get('kernel_version', 'unknown')}
  Boot Time: {inventory.get('boot_time') or 'unknown'}
  Current User: {inventory.get('current_user', 'unknown')}
  Non-interactive sudo: {_yes_no(bool(inventory.get('sudo_available')))}
  Time Sync: {_first_line(inventory.get('time_sync_status', ''), 'unknown')}

Network:
  Primary LAN IP: {inventory.get('primary_lan_ip') or 'unknown'}
  Bootstrap IPv4: {inventory.get('bootstrap_ipv4') or 'unknown'}
  Bootstrap IPv6: {inventory.get('bootstrap_ipv6') or 'unknown'}
  DNS Resolvers: {', '.join(dns_resolvers) if dns_resolvers else 'unknown'}

Network Interfaces:
{_block_or_none(inventory.get('network_interfaces', []))}

Default Route:
{indent(inventory.get('default_route') or 'unknown', '  ')}

Disk Usage:
{indent(inventory.get('disk_usage') or 'unknown', '  ')}

Memory and Swap:
{indent(inventory.get('memory_swap') or 'unknown', '  ')}

Detected:
{_block_or_none(_format_detected(inventory))}

Detected k3s/CNI/Styx Artifacts:
{_block_or_none(artifact_lines)}

Styx Reserved Ports:
{_block_or_none(_format_ports(conflicts))}

Blocking:
{_block_or_none(blocking)}

Warnings:
{_block_or_none(warnings)}

Next:
  MVP1 is read-only unless you run sysprep safe local or ports clear local.
  Run styxctl sysprep safe preview local to preview safe cleanup.
"""
    return text.rstrip() + "\n"


def save_report_bundle(report: dict[str, Any], text: str) -> dict[str, str]:
    hostname = report["inventory"].get("hostname") or "unknown-host"
    report_dir = Path.cwd() / "reports" / "styx" / hostname
    report_dir.mkdir(parents=True, exist_ok=True)

    json_path = report_dir / "sysprep-report.json"
    text_path = report_dir / "sysprep-report.txt"

    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    text_path.write_text(text, encoding="utf-8")

    return {"json": str(json_path), "text": str(text_path)}


def report_root(base: Path | None = None) -> Path:
    return (base or Path.cwd()) / "reports" / "styx"


def find_report_bundle(hostname: str | None = None, base: Path | None = None) -> dict[str, Path] | None:
    root = report_root(base)
    if not root.exists():
        return None

    if hostname:
        report_dir = root / hostname
        if not report_dir.is_dir():
            return None
    else:
        candidates = sorted(
            (path for path in root.iterdir() if path.is_dir()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        if not candidates:
            return None
        report_dir = candidates[0]

    json_path = report_dir / "sysprep-report.json"
    text_path = report_dir / "sysprep-report.txt"
    if not json_path.is_file() and not text_path.is_file():
        return None
    return {"json": json_path, "text": text_path, "dir": report_dir}


def _report_bundle(hostname: str | None = None, base: Path | None = None) -> dict[str, Path]:
    bundle = find_report_bundle(hostname=hostname, base=base)
    if bundle is None:
        raise FileNotFoundError("No saved sysprep report found under ./reports/styx/")
    return bundle


def load_saved_report(hostname: str | None = None, base: Path | None = None) -> dict[str, Any]:
    return json.loads(_report_bundle(hostname, base)["json"].read_text(encoding="utf-8"))


def load_saved_report_text(hostname: str | None = None, base: Path | None = None) -> str:
    bundle = _report_bundle(hostname, base)
    if bundle["text"].is_file():
        return bundle["text"].read_text(encoding="utf-8")
    return render_sysprep_text(load_saved_report(hostname=hostname, base=base))
