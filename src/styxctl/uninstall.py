"""Uninstall Styx config and k3s from a local gateway node.

Only removes artifacts that Styx installed. Preserves wg0 and
unrelated host infrastructure.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import find_config, load_config
from .install import STYX_SSHD_DROPIN, STYX_WG_DIR, _wireguard_settings
from .inventory import SystemInventory, collect_inventory
from .remediation import _run_mutating

K3S_UNINSTALL_SCRIPTS = (
    "/usr/local/bin/k3s-uninstall.sh",
    "/usr/local/bin/k3s-agent-uninstall.sh",
)


@dataclass(slots=True)
class UninstallStep:
    name: str
    category: str
    action: str
    status: str
    reason: str | None = None
    command_display: str | None = None
    detail: str | None = None
    requires_sudo: bool = True

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class UninstallPlan:
    hostname: str
    interface: str
    steps: list[UninstallStep] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "hostname": self.hostname,
            "interface": self.interface,
            "steps": [step.to_dict() for step in self.steps],
        }


def _detect_k3s_uninstall_script() -> str | None:
    for path in K3S_UNINSTALL_SCRIPTS:
        if Path(path).is_file():
            return path
    return None


def build_uninstall_plan(
    *,
    config_path: str | Path | None = None,
    inventory: SystemInventory | None = None,
) -> UninstallPlan:
    """Build a plan describing what would be removed on this node."""
    inventory = inventory or collect_inventory()
    resolved_path = Path(config_path) if config_path is not None else find_config()
    config = load_config(resolved_path) if resolved_path else {}
    interface, _port = _wireguard_settings(config)
    steps: list[UninstallStep] = []

    if interface in inventory.interface_names or interface in inventory.wireguard_interfaces:
        steps.append(
            UninstallStep(
                name="wg-down",
                category="wireguard",
                action="down",
                status="pending",
                reason=f"{interface} interface is currently up",
                command_display=f"sudo wg-quick down {interface}",
            )
        )
    else:
        steps.append(
            UninstallStep(
                name="wg-down",
                category="wireguard",
                action="down",
                status="skipped",
                reason=f"{interface} interface is not up",
            )
        )

    styx_conf = STYX_WG_DIR / f"{interface}.conf"
    if styx_conf.is_file():
        steps.append(
            UninstallStep(
                name="remove-wg-config",
                category="wireguard",
                action="remove",
                status="pending",
                reason=f"{styx_conf} exists",
                command_display=f"sudo rm -f {styx_conf}",
            )
        )
    else:
        steps.append(
            UninstallStep(
                name="remove-wg-config",
                category="wireguard",
                action="remove",
                status="skipped",
                reason=f"{styx_conf} not found",
            )
        )

    if STYX_SSHD_DROPIN.is_file():
        steps.append(
            UninstallStep(
                name="remove-gateway-ssh",
                category="gateway",
                action="remove",
                status="pending",
                reason=f"{STYX_SSHD_DROPIN} exists",
                command_display=(
                    f"sudo rm -f {STYX_SSHD_DROPIN}; "
                    "sudo systemctl reload ssh || sudo systemctl reload sshd"
                ),
            )
        )
    else:
        steps.append(
            UninstallStep(
                name="remove-gateway-ssh",
                category="gateway",
                action="remove",
                status="skipped",
                reason=f"{STYX_SSHD_DROPIN} not found",
            )
        )

    k3s_script = _detect_k3s_uninstall_script()
    if k3s_script:
        steps.append(
            UninstallStep(
                name="k3s-uninstall",
                category="platform",
                action="uninstall",
                status="pending",
                reason=f"k3s uninstall script found at {k3s_script}",
                command_display=f"sudo {k3s_script}",
            )
        )
    elif inventory.detected_binaries.get("k3s"):
        steps.append(
            UninstallStep(
                name="k3s-uninstall",
                category="platform",
                action="uninstall",
                status="deferred",
                reason=(
                    "k3s binary detected but no uninstall script found; "
                    "manually run k3s-uninstall.sh or k3s-agent-uninstall.sh"
                ),
            )
        )
    else:
        steps.append(
            UninstallStep(
                name="k3s-uninstall",
                category="platform",
                action="uninstall",
                status="skipped",
                reason="k3s is not installed on this node",
            )
        )

    return UninstallPlan(
        hostname=inventory.hostname,
        interface=interface,
        steps=steps,
    )


def _execute_uninstall_step(
    step: UninstallStep,
    *,
    interface: str,
    inventory: SystemInventory,
) -> UninstallStep:
    if step.status != "pending":
        return step

    if step.name == "wg-down":
        ok, detail = _run_mutating(
            ["wg-quick", "down", interface],
            use_sudo=True,
            sudo_available=inventory.sudo_available,
            timeout=30.0,
        )
    elif step.name == "remove-wg-config":
        styx_conf = str(STYX_WG_DIR / f"{interface}.conf")
        ok, detail = _run_mutating(
            ["rm", "-f", styx_conf],
            use_sudo=True,
            sudo_available=inventory.sudo_available,
        )
    elif step.name == "remove-gateway-ssh":
        ok, detail = _run_mutating(
            ["rm", "-f", str(STYX_SSHD_DROPIN)],
            use_sudo=True,
            sudo_available=inventory.sudo_available,
        )
        if ok:
            for unit in ("ssh", "sshd"):
                reload_ok, reload_detail = _run_mutating(
                    ["systemctl", "reload", unit],
                    use_sudo=True,
                    sudo_available=inventory.sudo_available,
                )
                if reload_ok:
                    detail = f"{detail}; reloaded {unit}"
                    break
            else:
                detail = f"{detail}; ssh reload failed: {reload_detail}"
    elif step.name == "k3s-uninstall":
        script = _detect_k3s_uninstall_script()
        if not script:
            step.status = "skipped"
            step.detail = "uninstall script no longer present"
            return step
        ok, detail = _run_mutating(
            [script],
            use_sudo=True,
            sudo_available=inventory.sudo_available,
            timeout=300.0,
        )
    else:
        step.status = "skipped"
        step.detail = "no executor"
        return step

    step.status = "removed" if ok else "failed"
    step.detail = detail
    return step


def apply_uninstall_plan(
    plan: UninstallPlan,
    *,
    inventory: SystemInventory | None = None,
) -> UninstallPlan:
    inventory = inventory or collect_inventory()
    updated_steps = [
        _execute_uninstall_step(step, interface=plan.interface, inventory=inventory)
        for step in plan.steps
    ]
    return UninstallPlan(
        hostname=plan.hostname,
        interface=plan.interface,
        steps=updated_steps,
    )


def render_uninstall_text(plan: UninstallPlan, *, dry_run: bool = False) -> str:
    mode = "dry-run (no changes made)" if dry_run else "apply"
    lines = [
        "Styx Uninstall Plan",
        "===================",
        "",
        f"Node: {plan.hostname}",
        f"Interface: {plan.interface}",
        f"Mode: {mode}",
        "",
        "Steps:",
    ]
    for step in plan.steps:
        lines.append(f"  - {step.name} [{step.status}] ({step.action})")
        if step.reason:
            lines.append(f"    reason: {step.reason}")
        if step.command_display:
            lines.append(f"    command: {step.command_display}")
        if step.detail:
            lines.append(f"    detail: {step.detail}")
    return "\n".join(lines).rstrip() + "\n"


def _build_uninstall_report(plan: UninstallPlan, *, dry_run: bool) -> dict[str, Any]:
    failed = [step for step in plan.steps if step.status == "failed"]
    pending = [step for step in plan.steps if step.status == "pending"]
    if dry_run:
        status = "DRY_RUN"
    elif failed:
        status = "FAILED"
    elif pending:
        status = "PARTIAL"
    else:
        status = "UNINSTALLED"

    return {
        "tool": "styxctl",
        "report_type": "uninstall",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hostname": plan.hostname,
        "status": status,
        "dry_run": dry_run,
        "plan": plan.to_dict(),
    }


def run_uninstall_local(
    *,
    dry_run: bool = False,
    yes: bool = False,
    config_path: str | Path | None = None,
) -> tuple[dict[str, Any], int]:
    inventory = collect_inventory()
    resolved_path = Path(config_path) if config_path is not None else find_config()
    plan = build_uninstall_plan(config_path=resolved_path, inventory=inventory)
    pending = [step for step in plan.steps if step.status == "pending"]

    if dry_run:
        return _build_uninstall_report(plan, dry_run=True), 0

    if not pending:
        return _build_uninstall_report(plan, dry_run=False), 0

    if not yes:
        report = _build_uninstall_report(plan, dry_run=True)
        report["status"] = "CONFIRMATION_REQUIRED"
        report["pending_count"] = len(pending)
        return report, 0

    applied = apply_uninstall_plan(plan, inventory=inventory)
    report = _build_uninstall_report(applied, dry_run=False)
    if any(step.status == "failed" for step in applied.steps):
        return report, 1
    return report, 0
