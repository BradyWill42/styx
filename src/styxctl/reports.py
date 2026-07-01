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
    conflicts_for_port,
    planned_protocols,
    port_purpose,
    port_purpose_for,
    styx_planned_listeners,
)


CRITICAL_PORTS = set(range(47800, 47809))


def _service_present(service: dict[str, str | None]) -> bool:
    values = {value for value in service.values() if value}
    return bool(values - {"missing", "inactive", "disabled", "not-found", "not found"})


def _artifact_warnings(inventory: SystemInventory) -> list[str]:
    warnings: list[str] = []
    for name, found in inventory.detected_artifacts.items():
        if found:
            pretty = name.replace("_", " ")
            warnings.append(f"Detected {pretty}: {', '.join(found)}")
    return warnings


def evaluate_readiness(inventory: SystemInventory) -> tuple[str, list[str], list[str]]:
    """Return status, warnings, and blocking reasons."""
    warnings: list[str] = []
    blocking: list[str] = []

    # 47800/tcp (gateway SSH) and 47801/tcp (k3s API) now co-locate with WireGuard/pistyx inside the
    # critical band. An occupant on a (port, protocol) Styx itself binds is EXPECTED on a re-run, so
    # it only warns; a foreign squatter on a critical port still blocks the install.
    styx_listeners = styx_planned_listeners()
    for conflict in inventory.ports.conflicts:
        message = (
            f"{conflict.port}/{conflict.protocol} occupied inside Styx reserved range"
            f" by {conflict.process_name or 'unknown process'}"
            f"{f' pid {conflict.pid}' if conflict.pid else ''}"
        )
        if conflict.port in CRITICAL_PORTS and (conflict.port, conflict.protocol) not in styx_listeners:
            blocking.append(message)
        else:
            warnings.append(message)

    if not inventory.ports.command_available:
        warnings.append("Could not run ss; Styx reserved port scan was not completed")
    elif inventory.ports.returncode not in (0, None):
        warnings.append("ss returned a nonzero exit code; port scan may be incomplete")
    elif inventory.ports.timed_out:
        warnings.append("ss timed out; port scan may be incomplete")

    warnings.extend(_artifact_warnings(inventory))

    if not inventory.sudo_available:
        warnings.append("Non-interactive sudo is not available for the current user")

    lowered_time = inventory.time_sync_status.lower()
    if "ntpsynchronized=no" in lowered_time or "system clock synchronized: no" in lowered_time:
        warnings.append("Time synchronization appears to be disabled or unsynchronized")

    if inventory.detected_binaries.get("k3s"):
        warnings.append(f"k3s binary detected at {inventory.detected_binaries['k3s']}")

    if _service_present(inventory.detected_services.get("k3s", {})):
        warnings.append("k3s.service appears to exist or be active")
    if _service_present(inventory.detected_services.get("k3s_agent", {})):
        warnings.append("k3s-agent.service appears to exist or be active")

    if blocking:
        status = "BLOCKED"
    elif warnings:
        status = "READY_WITH_WARNINGS"
    else:
        status = "READY"
    return status, warnings, blocking


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
        stripped = line.strip()
        if stripped:
            return stripped
    return fallback


def _block_or_none(lines: list[str], none_text: str = "none") -> str:
    if not lines:
        return f"  {none_text}"
    return "\n".join(f"  {line}" for line in lines)


def render_sysprep_text(report: dict[str, Any]) -> str:
    inventory_dict = report["inventory"]
    # The report data is JSON-friendly; the original object is not available here.
    # Re-read commonly used values from the dict to keep text rendering pure.
    status = report["status"]
    warnings = report["warnings"]
    blocking = report["blocking"]

    ports = inventory_dict["ports"]
    interface_names = set(inventory_dict.get("interface_names", []))
    wg_interfaces = set(inventory_dict.get("wireguard_interfaces", []))

    detected_lines = []
    detected_binaries = inventory_dict.get("detected_binaries", {})
    firewall_backend = inventory_dict.get("firewall_backend", {})
    detected_lines.append(f"k3s: {detected_binaries.get('k3s') or 'not installed'}")
    detected_lines.append(f"containerd: {detected_binaries.get('containerd') or 'not installed'}")
    detected_lines.append(f"Docker: {detected_binaries.get('docker') or 'not installed'}")
    detected_lines.append(f"Wazuh: {detected_binaries.get('wazuh-control') or detected_binaries.get('wazuh-agentd') or 'not installed'}")
    detected_lines.append(f"watchdog: {detected_binaries.get('watchdog') or 'not installed'}")
    detected_lines.append(f"wg0: {'present, preserved' if 'wg0' in interface_names or 'wg0' in wg_interfaces else 'absent'}")
    detected_lines.append(f"Styx interface: {_present_absent('Styx' in interface_names or 'Styx' in wg_interfaces)}")
    detected_lines.append(f"cni0: {_present_absent('cni0' in interface_names)}")
    detected_lines.append(f"flannel.1: {_present_absent('flannel.1' in interface_names)}")
    detected_lines.append(f"flannel-v6.1: {_present_absent('flannel-v6.1' in interface_names)}")
    detected_lines.append(f"firewall backend: {firewall_backend.get('preferred', 'unknown')}")

    def _occupied_line(conflict: dict[str, Any]) -> str:
        owner = conflict.get("process_name") or "unknown process"
        pid = f" pid={conflict.get('pid')}" if conflict.get("pid") else ""
        unit = f" unit={conflict.get('systemd_unit')}" if conflict.get("systemd_unit") else ""
        safe = "yes" if conflict.get("safe_to_stop") else "no"
        return f"{conflict.get('port')}/{conflict.get('protocol')}: occupied by {owner}{pid}{unit} safe_to_stop={safe}"

    port_lines: list[str] = [f"Range: {RESERVED_PORT_START}-{RESERVED_PORT_END}"]
    conflicts = ports.get("conflicts", [])
    for port in sorted(PORT_PLAN):
        planned = planned_protocols(port)
        port_conflicts = [conflict for conflict in conflicts if conflict.get("port") == port]
        # One line per planned protocol so co-located services (e.g. 47800/udp WireGuard +
        # 47800/tcp SSH) each report their own free/occupied state.
        for protocol in planned:
            matching = [conflict for conflict in port_conflicts if conflict.get("protocol") == protocol]
            if matching:
                port_lines.extend(_occupied_line(conflict) for conflict in matching)
            else:
                port_lines.append(f"{port}/{protocol}: free ({port_purpose_for(port, protocol)})")
        # A conflict on a planned port using an UNplanned protocol still deserves a line.
        for conflict in port_conflicts:
            if conflict.get("protocol") not in planned:
                port_lines.append(_occupied_line(conflict))

    extra_conflicts = [conflict for conflict in conflicts if conflict.get("port") not in PORT_PLAN]
    if extra_conflicts:
        port_lines.append("Additional occupied reserved ports:")
        for conflict in extra_conflicts:
            owner = conflict.get("process_name") or "unknown process"
            pid = f" pid={conflict.get('pid')}" if conflict.get("pid") else ""
            unit = f" unit={conflict.get('systemd_unit')}" if conflict.get("systemd_unit") else ""
            safe = "yes" if conflict.get("safe_to_stop") else "no"
            port_lines.append(
                f"{conflict.get('port')}/{conflict.get('protocol')}: occupied by {owner}{pid}{unit} "
                f"purpose={port_purpose(int(conflict.get('port')))} safe_to_stop={safe}"
            )

    artifacts = inventory_dict.get("detected_artifacts", {})
    artifact_lines: list[str] = []
    for name, found in artifacts.items():
        artifact_lines.append(f"{name.replace('_', ' ')}: {', '.join(found) if found else 'none'}")

    network_lines = inventory_dict.get("network_interfaces", [])
    dns_resolvers = inventory_dict.get("dns_resolvers", [])

    text = f"""Styx Sysprep Report
====================

Node: {inventory_dict.get('hostname', 'unknown')}
FQDN: {inventory_dict.get('fqdn', 'unknown')}
Status: {status}
Generated: {report.get('generated_at', 'unknown')}

System:
  OS: {inventory_dict.get('os_version', 'unknown')}
  Arch: {inventory_dict.get('architecture', 'unknown')}
  Kernel: {inventory_dict.get('kernel_version', 'unknown')}
  Boot Time: {inventory_dict.get('boot_time') or 'unknown'}
  Current User: {inventory_dict.get('current_user', 'unknown')}
  Non-interactive sudo: {_yes_no(bool(inventory_dict.get('sudo_available')))}
  Time Sync: {_first_line(inventory_dict.get('time_sync_status', ''), 'unknown')}

Network:
  Primary LAN IP: {inventory_dict.get('primary_lan_ip') or 'unknown'}
  Bootstrap IPv4: {inventory_dict.get('bootstrap_ipv4') or 'unknown'}
  Bootstrap IPv6: {inventory_dict.get('bootstrap_ipv6') or 'unknown'}
  DNS Resolvers: {', '.join(dns_resolvers) if dns_resolvers else 'unknown'}

Network Interfaces:
{_block_or_none(network_lines)}

Default Route:
{indent(inventory_dict.get('default_route') or 'unknown', '  ')}

Disk Usage:
{indent(inventory_dict.get('disk_usage') or 'unknown', '  ')}

Memory and Swap:
{indent(inventory_dict.get('memory_swap') or 'unknown', '  ')}

Detected:
{_block_or_none(detected_lines)}

Detected k3s/CNI/Styx Artifacts:
{_block_or_none(artifact_lines)}

Styx Reserved Ports:
{_block_or_none(port_lines)}

Blocking:
{_block_or_none(blocking)}

Warnings:
{_block_or_none(warnings)}

Next:
  MVP1 is read-only unless you run sysprep safe local or ports clear local.
  Run styxctl sysprep safe plan local to preview safe cleanup.
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


def load_saved_report(hostname: str | None = None, base: Path | None = None) -> dict[str, Any]:
    bundle = find_report_bundle(hostname=hostname, base=base)
    if bundle is None:
        raise FileNotFoundError("No saved sysprep report found under ./reports/styx/")
    return json.loads(bundle["json"].read_text(encoding="utf-8"))


def load_saved_report_text(hostname: str | None = None, base: Path | None = None) -> str:
    bundle = find_report_bundle(hostname=hostname, base=base)
    if bundle is None:
        raise FileNotFoundError("No saved sysprep report found under ./reports/styx/")
    if bundle["text"].is_file():
        return bundle["text"].read_text(encoding="utf-8")
    report = load_saved_report(hostname=hostname, base=base)
    return render_sysprep_text(report)
