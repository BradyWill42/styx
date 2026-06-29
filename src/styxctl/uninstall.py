"""Uninstall Styx config and k3s from local and cluster gateway nodes.

Only removes artifacts that Styx installed. Preserves wg0, persistent
runner configs under /etc/styx, and unrelated host infrastructure.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import shlex
from typing import Any, Callable

from .config import find_config, load_config
from .gateway import parse_gateway_ports
from .install import (
    STYX_SSHD_DROPIN,
    STYX_WG_DIR,
    WG0_CONFIG_PATH,
    _revoke_gateway_firewall,
    _wireguard_settings,
    build_firewall_revoke_shell,
)
from .inventory import SystemInventory, collect_inventory
from .k3s_cluster import _node_ssh_connection, _run_ssh_command
from .nodes import identify_local_node, parse_nodes
from .ports import ADMIN_SSH_PORT, RESERVED_PORT_END, RESERVED_PORT_START
from .remediation import _remove_path, _run_mutating


def _path_exists(path: Path) -> bool:
    """Return True if path exists, including when we lack read permission (sudo will handle it)."""
    try:
        return path.exists()
    except PermissionError:
        return True


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except PermissionError:
        return True


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except PermissionError:
        return True

K3S_UNINSTALL_SCRIPTS = (
    "/usr/local/bin/k3s-uninstall.sh",
    "/usr/local/bin/k3s-agent-uninstall.sh",
)
LEFTOVER_ARTIFACT_KEYS = (
    "old_k3s_files",
    "old_kubelet_state",
    "old_cni_configs",
    "old_flannel_state",
)
PRESERVED_INTERFACES = frozenset({"wg0"})
STYX_SITE_INTERFACE_PREFIX = "StyxSite"
DEFAULT_EGRESS_INTERFACE = "StyxEgress"
STYX_SYSTEM_CONFIG_PATH = Path("/etc/styx/styx.yaml")
PROTECTED_REMOVAL_PREFIXES = ("/etc/styx/",)
PROTECTED_REMOVAL_PATHS = frozenset({str(WG0_CONFIG_PATH)})
GITHUB_RUNNER_MARKERS = (".runner", "config.sh", "run.sh")
STYX_WG_CUSTOM_SYSTEMD_UNITS = ("styx.service", "styx-wireguard.service")

RunResult = tuple[bool, str]


@dataclass(slots=True)
class PreservedItem:
    category: str
    path: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


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
    wireguard_port: int = 47800
    gateway_ssh_port: int = 47810
    gateway_k3s_port: int = 47811
    steps: list[UninstallStep] = field(default_factory=list)
    preserved: list[PreservedItem] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "hostname": self.hostname,
            "interface": self.interface,
            "wireguard_port": self.wireguard_port,
            "gateway_ssh_port": self.gateway_ssh_port,
            "gateway_k3s_port": self.gateway_k3s_port,
            "steps": [step.to_dict() for step in self.steps],
            "preserved": [item.to_dict() for item in self.preserved],
        }


@dataclass(slots=True)
class ClusterUninstallNodePlan:
    node_name: str
    target_host: str
    local_execution: bool
    ssh_port: int
    ssh_jump: str | None
    steps: list[UninstallStep] = field(default_factory=list)
    status: str = "pending"
    detail: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "node_name": self.node_name,
            "target_host": self.target_host,
            "local_execution": self.local_execution,
            "ssh_port": self.ssh_port,
            "ssh_jump": self.ssh_jump,
            "status": self.status,
            "detail": self.detail,
            "steps": [step.to_dict() for step in self.steps],
        }


@dataclass(slots=True)
class ClusterUninstallPlan:
    hostname: str
    nodes: list[ClusterUninstallNodePlan] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "hostname": self.hostname,
            "nodes": [node.to_dict() for node in self.nodes],
        }


def _detect_k3s_uninstall_script() -> str | None:
    for path in K3S_UNINSTALL_SCRIPTS:
        if Path(path).is_file():
            return path
    return None


def _is_protected_removal_path(path: str, *, styx_interface: str) -> bool:
    """Return True when a detected path must never be removed by uninstall."""
    normalized = path.rstrip("/")
    if normalized in PROTECTED_REMOVAL_PATHS:
        return True
    if any(normalized.startswith(prefix.rstrip("/")) for prefix in PROTECTED_REMOVAL_PREFIXES):
        return True
    wg_prefix = f"{STYX_WG_DIR}/"
    if normalized.startswith(wg_prefix) and normalized.endswith(".conf"):
        conf_name = Path(normalized).name
        if conf_name != f"{styx_interface}.conf":
            return True
    return False


def _detect_github_runner_path() -> Path | None:
    candidates = (
        Path.home() / "actions-runner",
        Path("/actions-runner"),
        Path("/home/runner/actions-runner"),
    )
    for candidate in candidates:
        if any((candidate / marker).is_file() for marker in GITHUB_RUNNER_MARKERS):
            return candidate
    return None


def collect_preserved_items(
    inventory: SystemInventory,
    *,
    interface: str,
    config_path: Path | None,
) -> list[PreservedItem]:
    """Inventory host configs and services that uninstall intentionally leaves alone."""
    items: list[PreservedItem] = []

    if _is_file(WG0_CONFIG_PATH):
        items.append(
            PreservedItem(
                category="wireguard",
                path=str(WG0_CONFIG_PATH),
                reason="pre-existing tunnel; never modified by Styx",
            )
        )
    if "wg0" in inventory.interface_names or "wg0" in inventory.wireguard_interfaces:
        items.append(
            PreservedItem(
                category="wireguard",
                path="wg0 interface",
                reason="pre-existing tunnel interface",
            )
        )

    if _is_file(STYX_SYSTEM_CONFIG_PATH):
        items.append(
            PreservedItem(
                category="config",
                path=str(STYX_SYSTEM_CONFIG_PATH),
                reason="persistent runner/site config on self-hosted gateways",
            )
        )

    if _is_dir(STYX_WG_DIR):
        for conf in sorted(STYX_WG_DIR.glob("*.conf")):
            if conf.name in {f"{interface}.conf", "wg0.conf"}:
                continue
            items.append(
                PreservedItem(
                    category="wireguard",
                    path=str(conf),
                    reason="WireGuard config not managed by Styx",
                )
            )

    if config_path and config_path.is_file():
        items.append(
            PreservedItem(
                category="config",
                path=str(config_path),
                reason="operator config file in working directory",
            )
        )

    runner_path = _detect_github_runner_path()
    if runner_path is not None:
        items.append(
            PreservedItem(
                category="runner",
                path=str(runner_path),
                reason="GitHub Actions self-hosted runner registration",
            )
        )

    items.append(
        PreservedItem(
            category="packages",
            path="system packages (wireguard, curl, iproute2, ...)",
            reason="installed by Styx but not removed on uninstall",
        )
    )
    items.append(
        PreservedItem(
            category="gateway",
            path=f"sshd port {ADMIN_SSH_PORT} (default/admin)",
            reason=(
                "Styx never removes or reconfigures port 22; uninstall drops only "
                f"the Styx gateway SSH drop-in ({RESERVED_PORT_START}-{RESERVED_PORT_END})"
            ),
        )
    )
    return items


def _candidate_styx_wireguard_units(interface: str) -> tuple[str, ...]:
    return (f"wg-quick@{interface}.service", *STYX_WG_CUSTOM_SYSTEMD_UNITS)


def _wireguard_step_name(base: str, interface: str, primary_interface: str) -> str:
    return base if interface == primary_interface else f"{base}:{interface}"


def _is_wireguard_step(step: UninstallStep, base: str) -> bool:
    return step.name == base or step.name.startswith(f"{base}:")


def _wireguard_step_interface(step: UninstallStep, primary_interface: str) -> str:
    return step.name.split(":", 1)[1] if ":" in step.name else primary_interface


def _configured_egress_interface(config: dict[str, Any]) -> str:
    egress = config.get("egress", {})
    if not isinstance(egress, dict):
        return DEFAULT_EGRESS_INTERFACE
    interface = egress.get("interface", DEFAULT_EGRESS_INTERFACE)
    return interface if isinstance(interface, str) and interface else DEFAULT_EGRESS_INTERFACE


def _styx_owned_extra_wireguard_interfaces(
    config: dict[str, Any],
    inventory: SystemInventory,
    *,
    primary_interface: str,
) -> list[str]:
    egress_interface = _configured_egress_interface(config)
    candidates = set(inventory.interface_names) | set(inventory.wireguard_interfaces)
    extras: set[str] = set()
    for name in candidates:
        if name == primary_interface or name in PRESERVED_INTERFACES:
            continue
        if name in {DEFAULT_EGRESS_INTERFACE, egress_interface} or name.startswith(STYX_SITE_INTERFACE_PREFIX):
            extras.add(name)
    return sorted(extras)


def _styx_wireguard_systemd_artifacts(interface: str) -> list[Path]:
    artifacts: list[Path] = []
    candidates = [
        Path(f"/etc/systemd/system/wg-quick@{interface}.service"),
        Path(f"/etc/systemd/system/wg-quick@{interface}.service.d"),
        Path(f"/etc/systemd/system/multi-user.target.wants/wg-quick@{interface}.service"),
        Path("/etc/systemd/system/styx.service"),
        Path("/etc/systemd/system/styx-wireguard.service"),
        Path("/etc/systemd/system/multi-user.target.wants/styx.service"),
        Path("/etc/systemd/system/multi-user.target.wants/styx-wireguard.service"),
    ]
    for path in candidates:
        if path.exists():
            artifacts.append(path)
    return artifacts


def _styx_wireguard_service_configured(interface: str, inventory: SystemInventory) -> bool:
    if _styx_wireguard_systemd_artifacts(interface):
        return True
    styx_service = inventory.detected_services.get("styx", {})
    enabled = (styx_service.get("enabled") or "").lower()
    active = (styx_service.get("active") or "").lower()
    if enabled not in {"", "disabled", "missing"}:
        return True
    return active not in {"", "inactive", "missing", "failed"}


def build_wireguard_service_remove_shell(interface: str) -> str:
    """Shell snippet to stop/disable Styx WireGuard systemd units on a remote node."""
    if interface in PRESERVED_INTERFACES:
        return "true"
    commands: list[str] = []
    for unit in _candidate_styx_wireguard_units(interface):
        commands.append(f"systemctl stop {unit} 2>/dev/null || true")
        commands.append(f"systemctl disable {unit} 2>/dev/null || true")
    for path in _styx_wireguard_systemd_artifacts(interface):
        commands.append(f"rm -rf {shlex.quote(str(path))} 2>/dev/null || true")
    commands.append("systemctl daemon-reload 2>/dev/null || true")
    return " && ".join(commands) if commands else "true"


def _remove_styx_wireguard_service(interface: str, inventory: SystemInventory) -> RunResult:
    results: list[str] = []
    overall_ok = True
    for unit in _candidate_styx_wireguard_units(interface):
        for action in ("stop", "disable"):
            action_ok, action_detail = _run_mutating(
                ["systemctl", action, unit],
                use_sudo=True,
                sudo_available=inventory.sudo_available,
            )
            lowered = action_detail.lower()
            if action_ok:
                results.append(f"{unit}: {action} ok")
            elif any(token in lowered for token in ("not found", "does not exist", "not loaded", "no such")):
                results.append(f"{unit}: {action} skipped (not present)")
            else:
                results.append(f"{unit}: {action} failed ({action_detail})")
                overall_ok = False
    for path in _styx_wireguard_systemd_artifacts(interface):
        outcome = _remove_path(str(path), inventory)
        results.append(f"{path}: {outcome.detail}")
        if outcome.status == "failed":
            overall_ok = False
    reload_ok, reload_detail = _run_mutating(
        ["systemctl", "daemon-reload"],
        use_sudo=True,
        sudo_available=inventory.sudo_available,
    )
    results.append(f"daemon-reload: {reload_detail}")
    if not reload_ok:
        overall_ok = False
    return overall_ok, "; ".join(results)


def _leftover_artifact_paths(inventory: SystemInventory) -> list[str]:
    paths: list[str] = []
    for key in LEFTOVER_ARTIFACT_KEYS:
        paths.extend(inventory.detected_artifacts.get(key, []))
    return sorted(set(paths))


def _temp_styx_paths(inventory: SystemInventory) -> list[str]:
    return sorted(set(inventory.detected_artifacts.get("old_temporary_styx_files", [])))


def _append_k3s_uninstall_steps(steps: list[UninstallStep], inventory: SystemInventory) -> None:
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
                    "leftover artifact cleanup will run instead"
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


def _append_leftover_artifact_steps(
    steps: list[UninstallStep],
    inventory: SystemInventory,
    *,
    interface: str,
) -> None:
    for path in _leftover_artifact_paths(inventory):
        if _is_protected_removal_path(path, styx_interface=interface):
            continue
        steps.append(
            UninstallStep(
                name=f"remove-artifact:{path}",
                category="artifact",
                action="remove",
                status="pending",
                reason=f"leftover Styx/k3s artifact detected at {path}",
                command_display=f"sudo rm -rf {path}",
            )
        )


def _append_wireguard_steps(
    steps: list[UninstallStep],
    *,
    interface: str,
    primary_interface: str,
    inventory: SystemInventory,
) -> None:
    service_step = _wireguard_step_name("remove-styx-wireguard-service", interface, primary_interface)
    down_step = _wireguard_step_name("wg-down", interface, primary_interface)
    config_step = _wireguard_step_name("remove-wg-config", interface, primary_interface)
    if interface in PRESERVED_INTERFACES:
        steps.append(
            UninstallStep(
                name=down_step,
                category="wireguard",
                action="down",
                status="skipped",
                reason=f"{interface} is preserved and will not be modified",
            )
        )
        return

    if _styx_wireguard_service_configured(interface, inventory):
        unit_names = ", ".join(_candidate_styx_wireguard_units(interface))
        steps.append(
            UninstallStep(
                name=service_step,
                category="wireguard",
                action="stop",
                status="pending",
                reason=f"Styx WireGuard systemd unit(s) detected for {interface}",
                command_display=(
                    f"sudo systemctl stop/disable {unit_names}; "
                    "remove unit drop-ins under /etc/systemd/system; "
                    "sudo systemctl daemon-reload"
                ),
            )
        )
    else:
        steps.append(
            UninstallStep(
                name=service_step,
                category="wireguard",
                action="stop",
                status="skipped",
                reason=f"no Styx WireGuard systemd unit detected for {interface}",
            )
        )

    if interface in inventory.interface_names or interface in inventory.wireguard_interfaces:
        steps.append(
            UninstallStep(
                name=down_step,
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
                name=down_step,
                category="wireguard",
                action="down",
                status="skipped",
                reason=f"{interface} interface is not up",
            )
        )

    styx_conf = STYX_WG_DIR / f"{interface}.conf"
    if _is_file(styx_conf):
        steps.append(
            UninstallStep(
                name=config_step,
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
                name=config_step,
                category="wireguard",
                action="remove",
                status="skipped",
                reason=f"{styx_conf} not found",
            )
        )


def _append_gateway_steps(steps: list[UninstallStep]) -> None:
    if _is_file(STYX_SSHD_DROPIN):
        steps.append(
            UninstallStep(
                name="remove-gateway-ssh",
                category="gateway",
                action="remove",
                status="pending",
                reason=(
                    f"Remove Styx gateway SSH drop-in {STYX_SSHD_DROPIN}; "
                    f"port {ADMIN_SSH_PORT} and main sshd config unchanged"
                ),
                command_display=(
                    f"sudo rm -f {STYX_SSHD_DROPIN} "
                    f"(Styx {RESERVED_PORT_START}-{RESERVED_PORT_END} only); "
                    f"reload ssh/sshd; port {ADMIN_SSH_PORT} keeps listening"
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


def _append_firewall_step(
    steps: list[UninstallStep],
    *,
    wireguard_port: int,
    gateway_ssh_port: int,
    gateway_k3s_port: int,
) -> None:
    steps.append(
        UninstallStep(
            name="remove-gateway-firewall",
            category="firewall",
            action="revoke",
            status="pending",
            reason=(
                "Remove Styx reserved-range firewall rules from install "
                f"({RESERVED_PORT_START}-{RESERVED_PORT_END}): "
                f"{wireguard_port}/udp, {gateway_ssh_port}/tcp, {gateway_k3s_port}/tcp; "
                f"not port {ADMIN_SSH_PORT}"
            ),
            command_display=(
                f"revoke {wireguard_port}/udp, {gateway_ssh_port}/tcp, {gateway_k3s_port}/tcp "
                f"(Styx range only; port {ADMIN_SSH_PORT} untouched)"
            ),
        )
    )


def _append_temp_file_steps(steps: list[UninstallStep], inventory: SystemInventory) -> None:
    for path in _temp_styx_paths(inventory):
        steps.append(
            UninstallStep(
                name=f"remove-temp:{path}",
                category="file",
                action="remove",
                status="pending",
                reason="temporary Styx file detected",
                command_display=f"sudo rm -rf {path}",
                requires_sudo=path.startswith("/var/"),
            )
        )


def build_uninstall_plan(
    *,
    config_path: str | Path | None = None,
    inventory: SystemInventory | None = None,
) -> UninstallPlan:
    """Build a plan describing what would be removed on this node."""
    inventory = inventory or collect_inventory()
    resolved_path = Path(config_path) if config_path is not None else find_config()
    config = load_config(resolved_path) if resolved_path else {}
    interface, wireguard_port = _wireguard_settings(config)
    gateway = parse_gateway_ports(config)
    steps: list[UninstallStep] = []

    _append_k3s_uninstall_steps(steps, inventory)
    _append_leftover_artifact_steps(steps, inventory, interface=interface)
    _append_wireguard_steps(steps, interface=interface, primary_interface=interface, inventory=inventory)
    for extra_interface in _styx_owned_extra_wireguard_interfaces(
        config,
        inventory,
        primary_interface=interface,
    ):
        _append_wireguard_steps(
            steps,
            interface=extra_interface,
            primary_interface=interface,
            inventory=inventory,
        )
    _append_gateway_steps(steps)
    _append_firewall_step(
        steps,
        wireguard_port=wireguard_port,
        gateway_ssh_port=gateway.ssh,
        gateway_k3s_port=gateway.k3s_api,
    )
    _append_temp_file_steps(steps, inventory)
    preserved = collect_preserved_items(
        inventory,
        interface=interface,
        config_path=resolved_path,
    )

    return UninstallPlan(
        hostname=inventory.hostname,
        interface=interface,
        wireguard_port=wireguard_port,
        gateway_ssh_port=gateway.ssh,
        gateway_k3s_port=gateway.k3s_api,
        steps=steps,
        preserved=preserved,
    )


def _execute_uninstall_step(
    step: UninstallStep,
    *,
    plan: UninstallPlan,
    inventory: SystemInventory,
) -> UninstallStep:
    if step.status != "pending":
        return step

    interface = plan.interface

    if step.name == "k3s-uninstall":
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
    elif _is_wireguard_step(step, "remove-styx-wireguard-service"):
        interface = _wireguard_step_interface(step, plan.interface)
        ok, detail = _remove_styx_wireguard_service(interface, inventory)
    elif _is_wireguard_step(step, "wg-down"):
        interface = _wireguard_step_interface(step, plan.interface)
        ok, detail = _run_mutating(
            ["wg-quick", "down", interface],
            use_sudo=True,
            sudo_available=inventory.sudo_available,
            timeout=30.0,
        )
    elif _is_wireguard_step(step, "remove-wg-config"):
        interface = _wireguard_step_interface(step, plan.interface)
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
            reload_detail = "ssh reload failed"
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
                detail = f"{detail}; {reload_detail}"
    elif step.name == "remove-gateway-firewall":
        ok, detail = _revoke_gateway_firewall(
            plan.wireguard_port,
            plan.gateway_ssh_port,
            plan.gateway_k3s_port,
            inventory,
        )
    elif step.name.startswith("remove-artifact:") or step.name.startswith("remove-temp:"):
        path = step.name.split(":", 1)[1]
        if step.name.startswith("remove-artifact:") and _is_protected_removal_path(
            path,
            styx_interface=interface,
        ):
            step.status = "skipped"
            step.detail = "protected path; preserved by uninstall policy"
            return step
        outcome = _remove_path(path, inventory)
        ok = outcome.status == "applied"
        detail = outcome.detail
        if outcome.status == "skipped":
            step.status = "skipped"
            step.detail = detail
            return step
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
        _execute_uninstall_step(step, plan=plan, inventory=inventory)
        for step in plan.steps
    ]
    refreshed = collect_inventory()
    leftover_paths = _leftover_artifact_paths(refreshed)
    existing_names = {step.name for step in updated_steps}
    for path in leftover_paths:
        step_name = f"remove-artifact:{path}"
        if step_name in existing_names:
            continue
        if _is_protected_removal_path(path, styx_interface=plan.interface):
            continue
        extra = UninstallStep(
            name=step_name,
            category="artifact",
            action="remove",
            status="pending",
            reason=f"leftover artifact still present after uninstall: {path}",
            command_display=f"sudo rm -rf {path}",
        )
        updated_steps.append(_execute_uninstall_step(extra, plan=plan, inventory=inventory))

    return UninstallPlan(
        hostname=plan.hostname,
        interface=plan.interface,
        wireguard_port=plan.wireguard_port,
        gateway_ssh_port=plan.gateway_ssh_port,
        gateway_k3s_port=plan.gateway_k3s_port,
        steps=updated_steps,
        preserved=plan.preserved,
    )


def build_cluster_uninstall_plan(
    *,
    config_path: str | Path | None = None,
    inventory: SystemInventory | None = None,
    election_lan_ips: dict[str, str] | None = None,
    election_leader: str | None = None,
) -> ClusterUninstallPlan:
    inventory = inventory or collect_inventory()
    resolved_path = Path(config_path) if config_path is not None else find_config()
    config = load_config(resolved_path) if resolved_path else {}
    nodes = parse_nodes(config)
    local_node = identify_local_node(nodes, inventory, config)
    gateway = parse_gateway_ports(config)
    local_plan = build_uninstall_plan(config_path=resolved_path, inventory=inventory)

    node_plans: list[ClusterUninstallNodePlan] = []
    for node in nodes:
        connection = _node_ssh_connection(
            node,
            nodes,
            None,
            config,
            inventory=inventory,
            local_node=local_node,
            election_lan_ips=election_lan_ips,
            election_leader=election_leader,
            gateway_ssh_port=gateway.ssh,
        )
        node_plans.append(
            ClusterUninstallNodePlan(
                node_name=node.name,
                target_host=connection.target,
                local_execution=local_node is not None and local_node.name == node.name,
                ssh_port=connection.port,
                ssh_jump=connection.jump,
                steps=list(local_plan.steps),
            )
        )
    return ClusterUninstallPlan(hostname=inventory.hostname, nodes=node_plans)


def _remote_uninstall_command(plan: UninstallPlan) -> str:
    commands: list[str] = []
    for step in plan.steps:
        if step.status != "pending":
            continue
        if step.name == "k3s-uninstall":
            commands.append(
                "if [ -x /usr/local/bin/k3s-uninstall.sh ]; then /usr/local/bin/k3s-uninstall.sh; "
                "elif [ -x /usr/local/bin/k3s-agent-uninstall.sh ]; then /usr/local/bin/k3s-agent-uninstall.sh; fi"
            )
        elif _is_wireguard_step(step, "remove-styx-wireguard-service"):
            interface = _wireguard_step_interface(step, plan.interface)
            if interface not in PRESERVED_INTERFACES:
                commands.append(build_wireguard_service_remove_shell(interface))
        elif _is_wireguard_step(step, "wg-down"):
            interface = _wireguard_step_interface(step, plan.interface)
            if interface not in PRESERVED_INTERFACES:
                commands.append(f"wg-quick down {shlex.quote(interface)} || true")
        elif _is_wireguard_step(step, "remove-wg-config"):
            interface = _wireguard_step_interface(step, plan.interface)
            if interface not in PRESERVED_INTERFACES:
                commands.append(f"rm -f {shlex.quote(f'/etc/wireguard/{interface}.conf')}")
        elif step.name == "remove-gateway-ssh":
            commands.append("rm -f /etc/ssh/sshd_config.d/styx-gateway.conf")
            commands.append("systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true")
        elif step.name == "remove-gateway-firewall":
            commands.append(
                build_firewall_revoke_shell(
                    plan.wireguard_port,
                    plan.gateway_ssh_port,
                    plan.gateway_k3s_port,
                )
            )
        elif step.name.startswith("remove-artifact:") or step.name.startswith("remove-temp:"):
            path = step.name.split(":", 1)[1]
            if step.name.startswith("remove-artifact:") and _is_protected_removal_path(
                path,
                styx_interface=plan.interface,
            ):
                continue
            commands.append(f"rm -rf {shlex.quote(path)}")
    return " && ".join(commands) if commands else "true"


def apply_cluster_uninstall_plan(
    plan: ClusterUninstallPlan,
    *,
    config_path: str | Path | None = None,
    inventory: SystemInventory | None = None,
    runner: Callable[..., RunResult] | None = None,
) -> ClusterUninstallPlan:
    inventory = inventory or collect_inventory()
    resolved_path = Path(config_path) if config_path is not None else find_config()
    local_plan = build_uninstall_plan(config_path=resolved_path, inventory=inventory)
    ssh_runner = runner or _run_ssh_command

    for node_plan in plan.nodes:
        if node_plan.local_execution:
            applied = apply_uninstall_plan(local_plan, inventory=inventory)
            node_plan.steps = applied.steps
            node_plan.status = "removed" if not any(step.status == "failed" for step in applied.steps) else "failed"
            node_plan.detail = "local uninstall applied"
            continue

        remote_command = f"sudo bash -lc {shlex.quote(_remote_uninstall_command(local_plan))}"
        ok, detail = ssh_runner(
            node_plan.target_host,
            remote_command,
            port=node_plan.ssh_port,
            jump=node_plan.ssh_jump,
        )
        node_plan.status = "removed" if ok else "failed"
        node_plan.detail = detail

    return plan


def render_uninstall_text(plan: UninstallPlan, *, dry_run: bool = False) -> str:
    mode = "dry-run (no changes made)" if dry_run else "apply"
    pending = [step for step in plan.steps if step.status == "pending"]
    skipped = [step for step in plan.steps if step.status in {"skipped", "deferred"}]
    completed = [step for step in plan.steps if step.status not in {"pending", "skipped", "deferred"}]

    lines = [
        "Styx Uninstall Plan",
        "===================",
        "",
        f"Node: {plan.hostname}",
        f"Styx WireGuard interface: {plan.interface} "
        f"(removes systemd unit, /etc/wireguard/{plan.interface}.conf; never wg0)",
        f"Mode: {mode}",
        "",
    ]

    if pending:
        lines.append(f"Will remove ({len(pending)} step(s)):")
        for step in pending:
            lines.append(f"  - {step.name} [{step.status}] ({step.action})")
            if step.reason:
                lines.append(f"    reason: {step.reason}")
            if step.command_display:
                lines.append(f"    command: {step.command_display}")
        lines.append("")

    if skipped:
        lines.append(f"Skipped / deferred ({len(skipped)} step(s)):")
        for step in skipped:
            lines.append(f"  - {step.name} [{step.status}]")
            if step.reason:
                lines.append(f"    reason: {step.reason}")
        lines.append("")

    if completed and not dry_run:
        lines.append(f"Completed ({len(completed)} step(s)):")
        for step in completed:
            lines.append(f"  - {step.name} [{step.status}]")
            if step.detail:
                lines.append(f"    detail: {step.detail}")
        lines.append("")

    if plan.preserved:
        lines.append(f"Will preserve ({len(plan.preserved)} item(s); untouched):")
        for item in plan.preserved:
            lines.append(f"  - [{item.category}] {item.path}")
            lines.append(f"    reason: {item.reason}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_cluster_uninstall_text(plan: ClusterUninstallPlan, *, dry_run: bool = False) -> str:
    mode = "dry-run (no changes made)" if dry_run else "apply"
    lines = [
        "Styx Cluster Uninstall Plan",
        "===========================",
        "",
        f"Operator node: {plan.hostname}",
        f"Mode: {mode}",
        "",
        "Preserved on every node (never removed by styxctl uninstall):",
        f"  - sshd port {ADMIN_SSH_PORT} (admin/runner SSH; main sshd config untouched)",
        f"  - {WG0_CONFIG_PATH} and any non-Styx WireGuard configs",
        f"  - {STYX_SYSTEM_CONFIG_PATH} (self-hosted runner persistent config)",
        "  - GitHub Actions runner registration (if present)",
        "  - Operator styx.yaml in the working directory",
        "",
        "Nodes:",
    ]
    for node in plan.nodes:
        execution = "local" if node.local_execution else "ssh"
        pending_count = sum(1 for step in node.steps if step.status == "pending")
        lines.append(
            f"  - {node.node_name} [{node.status}] via {execution} -> {node.target_host} "
            f"({pending_count} pending step(s))"
        )
        if node.ssh_jump:
            lines.append(f"    jump: {node.ssh_jump}")
        if node.detail:
            lines.append(f"    detail: {node.detail}")
        if dry_run and pending_count:
            for step in node.steps:
                if step.status != "pending":
                    continue
                lines.append(f"    - {step.name}: {step.reason or step.action}")
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
        "preserved_count": len(plan.preserved),
        "plan": plan.to_dict(),
    }


def _build_cluster_uninstall_report(plan: ClusterUninstallPlan, *, dry_run: bool) -> dict[str, Any]:
    failed = [node for node in plan.nodes if node.status == "failed"]
    pending = [node for node in plan.nodes if node.status == "pending"]
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
        "report_type": "uninstall-cluster",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hostname": plan.hostname,
        "status": status,
        "dry_run": dry_run,
        "cluster": plan.to_dict(),
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


def run_uninstall_cluster(
    *,
    dry_run: bool = False,
    yes: bool = False,
    config_path: str | Path | None = None,
    runner: Callable[..., RunResult] | None = None,
) -> tuple[dict[str, Any], int]:
    inventory = collect_inventory()
    resolved_path = Path(config_path) if config_path is not None else find_config()
    plan = build_cluster_uninstall_plan(config_path=resolved_path, inventory=inventory)
    local_plan = build_uninstall_plan(config_path=resolved_path, inventory=inventory)
    local_has_pending = any(step.status == "pending" for step in local_plan.steps)
    pending = [node for node in plan.nodes if not node.local_execution or local_has_pending]

    if dry_run:
        return _build_cluster_uninstall_report(plan, dry_run=True), 0

    if not pending:
        return _build_cluster_uninstall_report(plan, dry_run=False), 0

    if not yes:
        report = _build_cluster_uninstall_report(plan, dry_run=True)
        report["status"] = "CONFIRMATION_REQUIRED"
        report["pending_count"] = len(plan.nodes)
        return report, 0

    applied = apply_cluster_uninstall_plan(
        plan,
        config_path=resolved_path,
        inventory=inventory,
        runner=runner,
    )
    report = _build_cluster_uninstall_report(applied, dry_run=False)
    if any(node.status == "failed" for node in applied.nodes):
        return report, 1
    return report, 0
