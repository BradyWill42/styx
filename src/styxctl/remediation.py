"""Safe local remediation for Styx MVP1.

Only acts on artifacts and processes already identified as safe by inventory
and port scanning. Never touches wg0, LAN networking, SSH, or unrelated services.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import os
import shutil
import signal
import subprocess
import time

from .inventory import SystemInventory
from .ports import PortConflict, check_reserved_ports

PRESERVED_INTERFACES = frozenset({"wg0"})
SAFE_SYSTEMD_UNITS = (
    "k3s.service",
    "k3s-agent.service",
)
SERVICE_KEYS = {
    "k3s.service": "k3s",
    "k3s-agent.service": "k3s_agent",
}
SAFE_SERVICE_NAME_TOKENS = ("k3s", "styx", "flannel", "cni")
ACTIVE_STATES = frozenset({"active", "activating", "reloading"})
ENABLED_STATES = frozenset({"enabled", "enabled-runtime"})
SYSPREP_SKIP_ARTIFACTS = frozenset({"old_temporary_styx_files", "old_cni_interfaces", "old_flannel_interfaces"})


@dataclass(slots=True)
class PlannedAction:
    category: str
    target: str
    action: str
    reason: str
    requires_sudo: bool = True

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class ActionOutcome:
    category: str
    target: str
    action: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class RemediationResult:
    dry_run: bool
    planned: list[PlannedAction] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    outcomes: list[ActionOutcome] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "dry_run": self.dry_run,
            "planned": [item.to_dict() for item in self.planned],
            "skipped": list(self.skipped),
            "outcomes": [item.to_dict() for item in self.outcomes],
        }


def _is_safe_service_unit(unit: str | None) -> bool:
    if not unit:
        return False
    lowered = unit.lower()
    if unit in SAFE_SYSTEMD_UNITS:
        return True
    return any(token in lowered for token in SAFE_SERVICE_NAME_TOKENS)


def _run_mutating(
    command: list[str],
    *,
    use_sudo: bool,
    sudo_available: bool,
    timeout: float = 30.0,
) -> tuple[bool, str]:
    executable = command[0]
    if use_sudo:
        if not sudo_available:
            return False, "non-interactive sudo is not available"
        sudo = shutil.which("sudo")
        if sudo is None:
            return False, "sudo command not found"
        command = [sudo, "-n", *command]

    if shutil.which(command[0]) is None:
        return False, f"command not found: {executable}"

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"timed out after {timeout} seconds"
    except OSError as exc:
        return False, str(exc)

    detail = (completed.stderr or completed.stdout or "").strip()
    if completed.returncode == 0:
        return True, detail or "ok"
    return False, detail or f"exit code {completed.returncode}"


def _systemctl_action(unit: str, action: str, inventory: SystemInventory) -> ActionOutcome:
    command = ["systemctl", action, unit]
    ok, detail = _run_mutating(
        command,
        use_sudo=True,
        sudo_available=inventory.sudo_available,
    )
    return ActionOutcome(
        category="service",
        target=unit,
        action=action,
        status="applied" if ok else "failed",
        detail=detail,
    )


def _remove_path(path: str, inventory: SystemInventory) -> ActionOutcome:
    if not os.path.exists(path):
        return ActionOutcome("file", path, "remove", "skipped", "path not present")

    if os.path.isdir(path):
        ok, detail = _run_mutating(
            ["rm", "-rf", path],
            use_sudo=True,
            sudo_available=inventory.sudo_available,
        )
    else:
        try:
            os.remove(path)
            ok, detail = True, "removed"
        except OSError as exc:
            ok, detail = _run_mutating(
                ["rm", "-f", path],
                use_sudo=True,
                sudo_available=inventory.sudo_available,
            )
            if not ok:
                detail = str(exc)

    return ActionOutcome(
        category="file",
        target=path,
        action="remove",
        status="applied" if ok else "failed",
        detail=detail,
    )


def _port_target(conflict: PortConflict) -> str:
    return f"{conflict.port}/{conflict.protocol}"


def _port_outcome(conflict: PortConflict, *, status: str, detail: str) -> ActionOutcome:
    return ActionOutcome("port", _port_target(conflict), "stop", status, detail)


def _stop_pid(conflict: PortConflict, inventory: SystemInventory) -> ActionOutcome:
    if conflict.pid is None:
        return _port_outcome(conflict, status="skipped", detail="no pid available")

    if conflict.systemd_unit and _is_safe_service_unit(conflict.systemd_unit):
        stop = _systemctl_action(conflict.systemd_unit, "stop", inventory)
        if stop.status == "applied":
            _systemctl_action(conflict.systemd_unit, "disable", inventory)
        return _port_outcome(conflict, status=stop.status, detail=f"{conflict.systemd_unit}: {stop.detail}")

    try:
        os.kill(conflict.pid, signal.SIGTERM)
    except OSError as exc:
        return _port_outcome(conflict, status="failed", detail=str(exc))

    time.sleep(0.2)
    try:
        os.kill(conflict.pid, 0)
        os.kill(conflict.pid, signal.SIGKILL)
    except OSError:
        pass

    return _port_outcome(
        conflict,
        status="applied",
        detail=f"stopped pid {conflict.pid} ({conflict.process_name or 'unknown'})",
    )


def _port_conflicts(inventory: SystemInventory, *, safe: bool) -> list[PortConflict]:
    return [conflict for conflict in inventory.ports.conflicts if conflict.safe_to_stop is safe]


def _service_needs_remediation(service: dict[str, str | None]) -> tuple[bool, bool]:
    active = (service.get("active") or "").lower()
    enabled = (service.get("enabled") or "").lower()
    return active in ACTIVE_STATES, enabled in ENABLED_STATES


def build_port_clear_plan(inventory: SystemInventory) -> RemediationResult:
    planned: list[PlannedAction] = []
    skipped: list[str] = []

    for conflict in _port_conflicts(inventory, safe=True):
        target = _port_target(conflict)
        if conflict.systemd_unit and _is_safe_service_unit(conflict.systemd_unit):
            planned.append(
                PlannedAction(
                    category="port",
                    target=target,
                    action="stop/disable unit",
                    reason=f"{conflict.systemd_unit} ({conflict.process_name or 'unknown'})",
                )
            )
        elif conflict.pid is not None:
            planned.append(
                PlannedAction(
                    category="port",
                    target=target,
                    action="stop process",
                    reason=f"pid {conflict.pid} ({conflict.process_name or 'unknown'})",
                    requires_sudo=False,
                )
            )
        else:
            skipped.append(f"{target} has no safe stop path")

    for conflict in _port_conflicts(inventory, safe=False):
        skipped.append(
            f"{conflict.port}/{conflict.protocol} occupied by "
            f"{conflict.process_name or 'unknown process'} (not marked safe to stop)"
        )

    return RemediationResult(dry_run=True, planned=planned, skipped=skipped)


def build_safe_sysprep_plan(inventory: SystemInventory) -> RemediationResult:
    result = build_port_clear_plan(inventory)

    for unit in SAFE_SYSTEMD_UNITS:
        needs_stop, needs_disable = _service_needs_remediation(
            inventory.detected_services.get(SERVICE_KEYS[unit], {})
        )
        if needs_stop or needs_disable:
            result.planned.append(
                PlannedAction(
                    category="service",
                    target=unit,
                    action="stop/disable",
                    reason="known Styx/k3s leftover service",
                )
            )

    for path in inventory.detected_artifacts.get("old_temporary_styx_files", []):
        result.planned.append(
            PlannedAction(
                category="file",
                target=path,
                action="remove",
                reason="old temporary Styx file",
                requires_sudo=path.startswith("/var/"),
            )
        )

    preserved = [name for name in inventory.interface_names if name in PRESERVED_INTERFACES]
    if preserved:
        result.skipped.append(f"preserved interfaces left untouched: {', '.join(preserved)}")

    for name, paths in inventory.detected_artifacts.items():
        if name in SYSPREP_SKIP_ARTIFACTS or not paths:
            continue
        pretty = name.replace("_", " ")
        suffix = "..." if len(paths) > 3 else ""
        result.skipped.append(
            f"{pretty} detected ({', '.join(paths[:3])}{suffix}); use MVP3 reset for deeper cleanup"
        )

    return result


def _apply_plan(
    inventory: SystemInventory,
    *,
    build_plan,
    dry_run: bool,
    apply,
) -> RemediationResult:
    plan = build_plan(inventory)
    plan.dry_run = dry_run
    if dry_run:
        return plan
    return apply(plan, inventory)


def apply_port_clear(inventory: SystemInventory, *, dry_run: bool = False) -> RemediationResult:
    def _apply(plan: RemediationResult, inv: SystemInventory) -> RemediationResult:
        for conflict in _port_conflicts(inv, safe=True):
            plan.outcomes.append(_stop_pid(conflict, inv))

        refreshed = check_reserved_ports()
        remaining = [item for item in refreshed.conflicts if item.safe_to_stop]
        if remaining:
            plan.skipped.append(
                f"{len(remaining)} safe conflict(s) still present after cleanup; re-run sysprep check local"
            )
        return plan

    return _apply_plan(inventory, build_plan=build_port_clear_plan, dry_run=dry_run, apply=_apply)


def apply_safe_sysprep(inventory: SystemInventory, *, dry_run: bool = False) -> RemediationResult:
    def _apply(plan: RemediationResult, inv: SystemInventory) -> RemediationResult:
        port_result = apply_port_clear(inv, dry_run=False)
        plan.outcomes.extend(port_result.outcomes)
        plan.skipped.extend(port_result.skipped)

        for unit in SAFE_SYSTEMD_UNITS:
            needs_stop, needs_disable = _service_needs_remediation(
                inv.detected_services.get(SERVICE_KEYS[unit], {})
            )
            if needs_stop:
                plan.outcomes.append(_systemctl_action(unit, "stop", inv))
            if needs_disable:
                plan.outcomes.append(_systemctl_action(unit, "disable", inv))

        for path in inv.detected_artifacts.get("old_temporary_styx_files", []):
            plan.outcomes.append(_remove_path(path, inv))
        return plan

    return _apply_plan(inventory, build_plan=build_safe_sysprep_plan, dry_run=dry_run, apply=_apply)


def render_remediation_summary(result: RemediationResult, *, title: str) -> str:
    lines = [title, "=" * len(title), ""]

    if result.dry_run:
        lines.append("Mode: dry-run (no changes made)")
    else:
        lines.append("Mode: apply")

    lines.append("")
    lines.append("Planned actions:")
    if result.planned:
        for item in result.planned:
            sudo = "sudo" if item.requires_sudo else "no-sudo"
            lines.append(f"  - [{item.category}] {item.action} {item.target} ({sudo})")
            lines.append(f"    reason: {item.reason}")
    else:
        lines.append("  none")

    if result.outcomes:
        lines.append("")
        lines.append("Outcomes:")
        for outcome in result.outcomes:
            lines.append(f"  - [{outcome.status}] {outcome.category} {outcome.action} {outcome.target}")
            if outcome.detail:
                lines.append(f"    {outcome.detail}")

    if result.skipped:
        lines.append("")
        lines.append("Skipped / follow-up:")
        for item in result.skipped:
            lines.append(f"  - {item}")

    return "\n".join(lines).rstrip() + "\n"
