"""Host prerequisite installation for Styx MVP2.

Installs only missing foundational packages and k3s. Preserves existing LAN
networking, SSH, wg0, and non-Styx services.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable

from .config import load_config
from .inventory import CommandResult, SystemInventory, collect_inventory, safe_run
from .reports import evaluate_readiness


CORE_APT_PACKAGES = (
    "iproute2",
    "wireguard-tools",
    "curl",
    "ca-certificates",
)

CORE_DNF_PACKAGES = CORE_APT_PACKAGES

BINARY_TO_PACKAGE = {
    "ss": "iproute2",
    "wg": "wireguard-tools",
    "curl": "curl",
}


@dataclass(slots=True)
class PrerequisiteStep:
    name: str
    category: str
    action: str
    status: str
    reason: str | None = None
    command: list[str] | None = None
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class PrerequisitePlan:
    hostname: str
    package_manager: str | None
    sysprep_status: str
    warnings: list[str]
    blocking: list[str]
    steps: list[PrerequisiteStep] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "hostname": self.hostname,
            "package_manager": self.package_manager,
            "sysprep_status": self.sysprep_status,
            "warnings": self.warnings,
            "blocking": self.blocking,
            "steps": [step.to_dict() for step in self.steps],
        }


@dataclass(slots=True)
class PrerequisiteResult:
    plan: PrerequisitePlan
    dry_run: bool
    forced: bool
    overall_status: str
    steps_completed: int
    steps_failed: int
    steps_skipped: int
    steps_deferred: int

    def to_dict(self) -> dict[str, object]:
        return {
            "tool": "styxctl",
            "report_type": "prerequisites_install",
            "command": "styxctl install prerequisites local",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "dry_run": self.dry_run,
            "forced": self.forced,
            "overall_status": self.overall_status,
            "steps_completed": self.steps_completed,
            "steps_failed": self.steps_failed,
            "steps_skipped": self.steps_skipped,
            "steps_deferred": self.steps_deferred,
            "plan": self.plan.to_dict(),
        }


def detect_package_manager() -> str | None:
    if shutil.which("apt-get"):
        return "apt"
    if shutil.which("dnf"):
        return "dnf"
    if shutil.which("yum"):
        return "yum"
    if shutil.which("apk"):
        return "apk"
    return None


def _artifact_present(inventory: SystemInventory, key: str) -> bool:
    return bool(inventory.detected_artifacts.get(key))


def _binary_missing(inventory: SystemInventory, binary: str) -> bool:
    return not inventory.detected_binaries.get(binary)


def _packages_for_inventory(inventory: SystemInventory, package_manager: str) -> list[str]:
    packages: list[str] = []
    package_set = set(CORE_APT_PACKAGES if package_manager == "apt" else CORE_DNF_PACKAGES)

    for binary, package in BINARY_TO_PACKAGE.items():
        if _binary_missing(inventory, binary) and package in package_set:
            packages.append(package)

    if package_manager == "apt" and "ca-certificates" not in packages:
        packages.append("ca-certificates")

    return sorted(set(packages))


def _siem_enabled(config: dict[str, Any]) -> bool:
    siem = config.get("siem")
    if not isinstance(siem, dict):
        return False
    return bool(siem.get("enabled"))


def _siem_provider(config: dict[str, Any]) -> str | None:
    siem = config.get("siem")
    if not isinstance(siem, dict):
        return None
    provider = siem.get("provider")
    return provider if isinstance(provider, str) else None


def build_prerequisite_plan(
    inventory: SystemInventory,
    config: dict[str, Any] | None = None,
) -> PrerequisitePlan:
    config = config or {}
    status, warnings, blocking = evaluate_readiness(inventory)
    package_manager = detect_package_manager()
    steps: list[PrerequisiteStep] = []

    packages = _packages_for_inventory(inventory, package_manager) if package_manager else []
    if packages and package_manager == "apt":
        steps.append(
            PrerequisiteStep(
                name="system-packages",
                category="packages",
                action="install",
                status="pending",
                reason=f"Missing packages for detected binaries: {', '.join(packages)}",
                command=[
                    "sudo",
                    "env",
                    "DEBIAN_FRONTEND=noninteractive",
                    "apt-get",
                    "install",
                    "-y",
                    "-qq",
                    *packages,
                ],
            )
        )
    elif packages and package_manager in {"dnf", "yum"}:
        manager = package_manager
        steps.append(
            PrerequisiteStep(
                name="system-packages",
                category="packages",
                action="install",
                status="pending",
                reason=f"Missing packages for detected binaries: {', '.join(packages)}",
                command=["sudo", manager, "install", "-y", *packages],
            )
        )
    elif packages:
        steps.append(
            PrerequisiteStep(
                name="system-packages",
                category="packages",
                action="install",
                status="deferred",
                reason=f"Packages needed ({', '.join(packages)}) but package manager is unsupported",
            )
        )
    else:
        steps.append(
            PrerequisiteStep(
                name="system-packages",
                category="packages",
                action="verify",
                status="skipped",
                reason="Required system packages already present",
            )
        )

    if _binary_missing(inventory, "k3s"):
        if _artifact_present(inventory, "old_k3s_files") or _artifact_present(inventory, "old_kubelet_state"):
            steps.append(
                PrerequisiteStep(
                    name="k3s",
                    category="platform",
                    action="install",
                    status="deferred",
                    reason="Existing k3s artifacts detected; run styxctl sysprep safe local before installing k3s",
                )
            )
        else:
            steps.append(
                PrerequisiteStep(
                    name="k3s",
                    category="platform",
                    action="install",
                    status="pending",
                    reason="k3s binary not detected",
                    command=["curl", "-sfL", "https://get.k3s.io", "|", "sudo", "sh", "-"],
                )
            )
    else:
        steps.append(
            PrerequisiteStep(
                name="k3s",
                category="platform",
                action="verify",
                status="skipped",
                reason=f"k3s already present at {inventory.detected_binaries['k3s']}",
            )
        )

    if _siem_enabled(config) and _siem_provider(config) == "wazuh":
        if _binary_missing(inventory, "wazuh-control") and _binary_missing(inventory, "wazuh-agentd"):
            steps.append(
                PrerequisiteStep(
                    name="wazuh-agent",
                    category="siem",
                    action="install",
                    status="deferred",
                    reason="Wazuh install is config-enabled but deferred to a later MVP; install manually for now",
                )
            )
        else:
            steps.append(
                PrerequisiteStep(
                    name="wazuh-agent",
                    category="siem",
                    action="verify",
                    status="skipped",
                    reason="Wazuh binaries already present",
                )
            )

    if _binary_missing(inventory, "watchdog"):
        steps.append(
            PrerequisiteStep(
                name="watchdog",
                category="monitoring",
                action="install",
                status="deferred",
                reason="watchdog install is deferred to a later MVP",
            )
        )
    else:
        steps.append(
            PrerequisiteStep(
                name="watchdog",
                category="monitoring",
                action="verify",
                status="skipped",
                reason=f"watchdog already present at {inventory.detected_binaries['watchdog']}",
            )
        )

    return PrerequisitePlan(
        hostname=inventory.hostname,
        package_manager=package_manager,
        sysprep_status=status,
        warnings=warnings,
        blocking=blocking,
        steps=steps,
    )


def _run_shell_pipeline(command: list[str], timeout: float = 600.0) -> tuple[int | None, str, str, str | None]:
    if "|" not in command:
        return _run_command(command, timeout=timeout)

    segments: list[list[str]] = []
    current: list[str] = []
    for token in command:
        if token == "|":
            if current:
                segments.append(current)
            current = []
        else:
            current.append(token)
    if current:
        segments.append(current)

    if len(segments) != 2:
        return None, "", "", "unsupported shell pipeline"

    left, right = segments
    left_exec = shutil.which(left[0])
    right_exec = shutil.which(right[0])
    if not left_exec or not right_exec:
        return None, "", "", "pipeline command not found"

    try:
        left_proc = subprocess.Popen(
            [left_exec, *left[1:]],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        right_proc = subprocess.Popen(
            [right_exec, *right[1:]],
            stdin=left_proc.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if left_proc.stdout is not None:
            left_proc.stdout.close()
        stdout, stderr = right_proc.communicate(timeout=timeout)
        left_proc.wait(timeout=1)
        return right_proc.returncode, stdout or "", stderr or "", None
    except subprocess.TimeoutExpired:
        return None, "", "", f"timed out after {timeout} seconds"
    except OSError as exc:
        return None, "", "", str(exc)


def _run_command(command: list[str], timeout: float = 600.0) -> tuple[int | None, str, str, str | None]:
    executable = shutil.which(command[0])
    if executable is None:
        return None, "", "", f"command not found: {command[0]}"

    try:
        completed = subprocess.run(
            [executable, *command[1:]],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, "", "", f"timed out after {timeout} seconds"
    except OSError as exc:
        return None, "", "", str(exc)

    return completed.returncode, completed.stdout or "", completed.stderr or "", None


def _apt_install(packages: list[str], runner: Callable[[list[str], float], tuple[int | None, str, str, str | None]]) -> tuple[int | None, str, str, str | None]:
    update_code, update_out, update_err, update_error = runner(
        ["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update", "-qq"],
        timeout=300.0,
    )
    if update_error or update_code not in (0, None):
        return update_code, update_out, update_err, update_error or "apt-get update failed"

    return runner(
        [
            "sudo",
            "env",
            "DEBIAN_FRONTEND=noninteractive",
            "apt-get",
            "install",
            "-y",
            "-qq",
            *packages,
        ],
        timeout=600.0,
    )


def execute_step(
    step: PrerequisiteStep,
    package_manager: str | None,
    runner: Callable[[list[str], float], tuple[int | None, str, str, str | None]] = _run_command,
) -> PrerequisiteStep:
    if step.status != "pending" or not step.command:
        return step

    if step.name == "system-packages" and package_manager == "apt":
        packages = [token for token in step.command if token not in {
            "sudo",
            "env",
            "DEBIAN_FRONTEND=noninteractive",
            "apt-get",
            "install",
            "-y",
            "-qq",
        }]
        returncode, stdout, stderr, error = _apt_install(packages, runner)
    elif step.name == "k3s":
        returncode, stdout, stderr, error = _run_shell_pipeline(step.command, timeout=900.0)
    else:
        returncode, stdout, stderr, error = runner(step.command, timeout=600.0)

    step.stdout = stdout
    step.stderr = stderr
    if error:
        step.status = "failed"
        step.reason = error
    elif returncode == 0:
        step.status = "installed"
    else:
        step.status = "failed"
        step.reason = f"command exited with code {returncode}"
    return step


def execute_prerequisite_plan(
    plan: PrerequisitePlan,
    *,
    dry_run: bool = False,
    runner: Callable[[list[str], float], tuple[int | None, str, str, str | None]] = _run_command,
) -> PrerequisiteResult:
    steps = list(plan.steps)
    if not dry_run:
        for index, step in enumerate(steps):
            if step.status == "pending":
                steps[index] = execute_step(step, plan.package_manager, runner=runner)

    counts = {
        "installed": sum(1 for step in steps if step.status == "installed"),
        "failed": sum(1 for step in steps if step.status == "failed"),
        "skipped": sum(1 for step in steps if step.status == "skipped"),
        "deferred": sum(1 for step in steps if step.status == "deferred"),
    }

    if dry_run:
        overall = "DRY_RUN"
    elif counts["failed"]:
        overall = "FAILED"
    elif plan.sysprep_status == "BLOCKED":
        overall = "BLOCKED"
    elif counts["installed"]:
        overall = "INSTALLED"
    elif counts["deferred"] and not counts["installed"]:
        overall = "DEFERRED"
    else:
        overall = "READY"

    updated_plan = PrerequisitePlan(
        hostname=plan.hostname,
        package_manager=plan.package_manager,
        sysprep_status=plan.sysprep_status,
        warnings=plan.warnings,
        blocking=plan.blocking,
        steps=steps,
    )
    return PrerequisiteResult(
        plan=updated_plan,
        dry_run=dry_run,
        forced=False,
        overall_status=overall,
        steps_completed=counts["installed"],
        steps_failed=counts["failed"],
        steps_skipped=counts["skipped"],
        steps_deferred=counts["deferred"],
    )


def render_prerequisites_text(result: PrerequisiteResult) -> str:
    plan = result.plan
    lines = [
        "Styx Prerequisites Install Report",
        "=================================",
        "",
        f"Node: {plan.hostname}",
        f"Status: {result.overall_status}",
        f"Sysprep gate: {plan.sysprep_status}",
        f"Dry run: {'yes' if result.dry_run else 'no'}",
        f"Package manager: {plan.package_manager or 'unsupported'}",
        "",
        "Steps:",
    ]

    for step in plan.steps:
        command = " ".join(step.command) if step.command else "-"
        lines.append(f"  - {step.name} [{step.status}] ({step.action})")
        lines.append(f"    reason: {step.reason or 'none'}")
        lines.append(f"    command: {command}")

    lines.extend(
        [
            "",
            "Blocking:",
            *([f"  - {item}" for item in plan.blocking] or ["  none"]),
            "",
            "Warnings:",
            *([f"  - {item}" for item in plan.warnings] or ["  none"]),
            "",
            "Summary:",
            f"  installed: {result.steps_completed}",
            f"  failed: {result.steps_failed}",
            f"  skipped: {result.steps_skipped}",
            f"  deferred: {result.steps_deferred}",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def save_prerequisites_report(result: PrerequisiteResult, text: str) -> dict[str, str]:
    hostname = result.plan.hostname or "unknown-host"
    report_dir = Path.cwd() / "reports" / "styx" / hostname
    report_dir.mkdir(parents=True, exist_ok=True)

    json_path = report_dir / "prerequisites-install-report.json"
    text_path = report_dir / "prerequisites-install-report.txt"
    json_path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    text_path.write_text(text, encoding="utf-8")
    return {"json": str(json_path), "text": str(text_path)}


def run_prerequisites_install(
    *,
    dry_run: bool = False,
    force: bool = False,
    config_path: str | Path | None = None,
    inventory: SystemInventory | None = None,
    runner: Callable[[list[str], float], tuple[int | None, str, str, str | None]] = _run_command,
) -> PrerequisiteResult:
    inventory = inventory or collect_inventory()
    config = load_config(config_path)
    plan = build_prerequisite_plan(inventory, config)

    if plan.sysprep_status == "BLOCKED" and not force and not dry_run:
        result = PrerequisiteResult(
            plan=plan,
            dry_run=dry_run,
            forced=force,
            overall_status="BLOCKED",
            steps_completed=0,
            steps_failed=0,
            steps_skipped=sum(1 for step in plan.steps if step.status == "skipped"),
            steps_deferred=sum(1 for step in plan.steps if step.status == "deferred"),
        )
        return result

    if not dry_run and not inventory.sudo_available:
        blocked_plan = PrerequisitePlan(
            hostname=plan.hostname,
            package_manager=plan.package_manager,
            sysprep_status=plan.sysprep_status,
            warnings=[*plan.warnings, "Non-interactive sudo is required for prerequisite installation"],
            blocking=plan.blocking,
            steps=plan.steps,
        )
        return PrerequisiteResult(
            plan=blocked_plan,
            dry_run=dry_run,
            forced=force,
            overall_status="BLOCKED",
            steps_completed=0,
            steps_failed=0,
            steps_skipped=sum(1 for step in plan.steps if step.status == "skipped"),
            steps_deferred=sum(1 for step in plan.steps if step.status == "deferred"),
        )

    result = execute_prerequisite_plan(plan, dry_run=dry_run, runner=runner)
    result.forced = force
    if force and plan.sysprep_status == "BLOCKED" and result.overall_status not in {"FAILED", "BLOCKED"}:
        result.overall_status = "INSTALLED_WITH_FORCED_BLOCK"
    return result


def verify_post_install() -> dict[str, CommandResult]:
    """Re-check a small set of commands after installation."""
    checks = {
        "ss": ["ss", "-V"],
        "wg": ["wg", "--version"],
        "k3s": ["k3s", "--version"],
    }
    return {name: safe_run(name, command, timeout=5.0) for name, command in checks.items()}
