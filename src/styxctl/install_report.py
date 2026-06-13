"""Install report rendering and persistence for MVP2."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def render_install_text(report: dict[str, Any]) -> str:
    plan = report.get("plan", {})
    steps = plan.get("steps", [])
    gate = report.get("gate", {})
    health = report.get("health", {})

    lines = [
        "Styx Install Report",
        "===================",
        "",
        f"Node: {report.get('hostname', 'unknown')}",
        f"Command: {report.get('command', 'unknown')}",
        f"Status: {report.get('status', 'unknown')}",
        f"Generated: {report.get('generated_at', 'unknown')}",
        f"Dry run: {'yes' if report.get('dry_run') else 'no'}",
        "",
        "Gate:",
        f"  config path: {gate.get('config_path') or 'not found'}",
        f"  config status: {gate.get('config_status', 'unknown')}",
        f"  sysprep status: {gate.get('sysprep_status', 'unknown')}",
        f"  sudo available: {'yes' if gate.get('sudo_available') else 'no'}",
        "",
        "Planned / executed steps:",
    ]

    if steps:
        for step in steps:
            command = step.get("command_display") or " ".join(step.get("command", []) or []) or "-"
            lines.append(f"  - {step.get('name')} [{step.get('status')}] ({step.get('action')})")
            lines.append(f"    reason: {step.get('reason') or 'none'}")
            lines.append(f"    command: {command}")
            if step.get("detail"):
                lines.append(f"    detail: {step['detail']}")
    else:
        lines.append("  none")

    if health:
        lines.extend(
            [
                "",
                "Health:",
                f"  k3s installed: {'yes' if health.get('k3s_installed') else 'no'}",
                f"  k3s active: {'yes' if health.get('k3s_active') else 'no'}",
                f"  k3s version: {health.get('k3s_version') or 'unknown'}",
                f"  kubectl available: {'yes' if health.get('kubectl_available') else 'no'}",
                f"  wg binary: {'yes' if health.get('wg_binary') else 'no'}",
                f"  Styx interface up: {'yes' if health.get('styx_interface_up') else 'no'}",
                f"  Styx port listening: {'yes' if health.get('styx_port_listening') else 'no'}",
                f"  wg0 preserved: {'yes' if health.get('wg0_preserved') else 'no'}",
                f"  critical ports clear: {'yes' if health.get('critical_ports_clear') else 'no'}",
                f"  local cluster node: {health.get('local_node') or 'unmatched'}",
                f"  cluster nodes configured: {health.get('cluster_node_count', 0)}",
            ]
        )

    cluster = report.get("cluster")
    if cluster:
        lines.extend(["", "Cluster plan:", f"  init node: {cluster.get('init_node', 'unknown')}"])
        for node in cluster.get("nodes", []):
            node_info = node.get("node", {})
            lines.append(
                f"  - {node_info.get('name')} ({node.get('role')}) "
                f"[{node.get('status')}] -> {node.get('command_display')}"
            )

    cluster_health = report.get("cluster_health")
    if cluster_health:
        lines.extend(["", "Cluster health:", f"  healthy: {'yes' if cluster_health.get('healthy') else 'no'}"])
        if cluster_health.get("kubectl_nodes"):
            lines.append(f"  kubectl nodes: {', '.join(cluster_health['kubectl_nodes'])}")

    blocking = report.get("blocking", [])
    warnings = report.get("warnings", [])
    issues = report.get("issues", [])

    lines.extend(["", "Blocking:"])
    lines.extend([f"  - {item}" for item in blocking] or ["  none"])
    lines.extend(["", "Warnings:"])
    lines.extend([f"  - {item}" for item in warnings] or ["  none"])
    if issues:
        lines.extend(["", "Issues:"])
        lines.extend([f"  - {item}" for item in issues])

    return "\n".join(lines).rstrip() + "\n"


def save_install_report(report: dict[str, Any], text: str) -> dict[str, str]:
    hostname = report.get("hostname") or "unknown-host"
    report_dir = Path.cwd() / "reports" / "styx" / hostname
    report_dir.mkdir(parents=True, exist_ok=True)

    json_path = report_dir / "install-report.json"
    text_path = report_dir / "install-report.txt"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    text_path.write_text(text, encoding="utf-8")
    return {"json": str(json_path), "text": str(text_path)}
