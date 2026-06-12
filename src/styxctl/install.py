"""Local prerequisite installation for Styx MVP2.

Installs k3s and the Styx WireGuard interface on a single gateway node.
Preserves wg0 and unrelated host infrastructure.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import os
from pathlib import Path
import secrets
import shutil
import subprocess
from typing import Any, Callable

from .config import config_status, find_config, load_config, validate_config
from .inventory import SystemInventory, collect_inventory, safe_run
from .k3s_cluster import (
    ClusterPlan,
    apply_cluster_node_plan,
    assess_cluster_nodes,
    build_cluster_plan,
    fetch_join_token_from_init,
    k3s_install_spec,
    _run_ssh_command,
)
from .nodes import identify_local_node, init_server_node, parse_nodes, validate_nodes
from .remediation import _run_mutating
from .reports import CRITICAL_PORTS, evaluate_readiness

PRESERVED_INTERFACES = frozenset({"wg0"})
WG0_CONFIG_PATH = Path("/etc/wireguard/wg0.conf")
STYX_WG_DIR = Path("/etc/wireguard")

APT_PACKAGES = ("iproute2", "wireguard", "wireguard-tools", "curl", "ca-certificates")
DNF_PACKAGES = APT_PACKAGES


@dataclass(slots=True)
class Wg0Snapshot:
    present: bool
    in_interface_list: bool
    in_wireguard_list: bool
    config_exists: bool
    config_mtime: float | None = None
    config_hash: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class InstallStep:
    name: str
    category: str
    action: str
    status: str
    reason: str | None = None
    command: list[str] | None = None
    command_display: str | None = None
    detail: str | None = None
    requires_sudo: bool = True

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class InstallPlan:
    hostname: str
    config_path: str | None
    config_status: str
    sysprep_status: str
    warnings: list[str]
    blocking: list[str]
    wg0_before: Wg0Snapshot
    local_node: str | None = None
    cluster_plan: ClusterPlan | None = None
    steps: list[InstallStep] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "hostname": self.hostname,
            "config_path": self.config_path,
            "config_status": self.config_status,
            "sysprep_status": self.sysprep_status,
            "warnings": self.warnings,
            "blocking": self.blocking,
            "wg0_before": self.wg0_before.to_dict(),
            "local_node": self.local_node,
            "cluster_plan": self.cluster_plan.to_dict() if self.cluster_plan else None,
            "steps": [step.to_dict() for step in self.steps],
        }


@dataclass(slots=True)
class InstallGateResult:
    ok: bool
    message: str | None
    config: dict[str, Any]
    config_path: Path | None
    config_status_value: str
    inventory: SystemInventory
    sysprep_status: str
    warnings: list[str]
    blocking: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "message": self.message,
            "config_path": str(self.config_path) if self.config_path else None,
            "config_status": self.config_status_value,
            "sysprep_status": self.sysprep_status,
            "sudo_available": self.inventory.sudo_available,
            "warnings": self.warnings,
            "blocking": self.blocking,
        }


@dataclass(slots=True)
class InstallHealth:
    healthy: bool
    k3s_installed: bool
    k3s_active: bool
    k3s_version: str | None
    kubectl_available: bool
    wg_binary: bool
    styx_interface_up: bool
    styx_port_listening: bool
    wg0_preserved: bool
    config_status: str
    config_path: str | None
    critical_ports_clear: bool
    cluster_healthy: bool | None
    cluster_node_count: int
    local_node: str | None
    issues: list[str]
    warnings: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


RunResult = tuple[bool, str]


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


def _hash_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def capture_wg0_snapshot(inventory: SystemInventory) -> Wg0Snapshot:
    present = "wg0" in inventory.interface_names or "wg0" in inventory.wireguard_interfaces
    config_exists = WG0_CONFIG_PATH.is_file()
    return Wg0Snapshot(
        present=present,
        in_interface_list="wg0" in inventory.interface_names,
        in_wireguard_list="wg0" in inventory.wireguard_interfaces,
        config_exists=config_exists,
        config_mtime=WG0_CONFIG_PATH.stat().st_mtime if config_exists else None,
        config_hash=_hash_file(WG0_CONFIG_PATH) if config_exists else None,
    )


def verify_wg0_preserved(before: Wg0Snapshot, after: Wg0Snapshot) -> tuple[bool, str | None]:
    if before.present != after.present:
        return False, "wg0 presence changed during install"
    if before.config_exists != after.config_exists:
        return False, "wg0 config presence changed during install"
    if before.config_exists and before.config_hash != after.config_hash:
        return False, "wg0 config content changed during install"
    return True, None


def _wireguard_settings(config: dict[str, Any]) -> tuple[str, int]:
    wireguard = config.get("wireguard", {})
    interface = wireguard.get("interface", "Styx")
    port = wireguard.get("port", 47800)
    if not isinstance(interface, str):
        interface = "Styx"
    if not isinstance(port, int):
        port = 47800
    return interface, port


def _k3s_install_args(config: dict[str, Any]) -> list[str]:
    cluster = config.get("cluster", {})
    network = config.get("network", {})
    mode = cluster.get("mode", "dual-stack")
    args: list[str] = []

    if mode in {"dual-stack", "ipv4-only"}:
        pod_ipv4 = network.get("pod_ipv4")
        service_ipv4 = network.get("service_ipv4")
        if isinstance(pod_ipv4, str):
            args.extend(["--cluster-cidr", pod_ipv4])
        if isinstance(service_ipv4, str):
            args.extend(["--service-cidr", service_ipv4])

    if mode in {"dual-stack", "ipv6-only"}:
        pod_ipv6 = network.get("pod_ipv6")
        service_ipv6 = network.get("service_ipv6")
        if isinstance(pod_ipv6, str):
            args.extend(["--cluster-cidr-v6", pod_ipv6])
        if isinstance(service_ipv6, str):
            args.extend(["--service-cidr-v6", service_ipv6])

    return args


def _wireguard_addresses(config: dict[str, Any], inventory: SystemInventory) -> list[str]:
    network = config.get("network", {})
    addresses: list[str] = []

    mesh_ipv4 = network.get("mesh_ipv4")
    if isinstance(mesh_ipv4, str):
        net4 = ipaddress.ip_network(mesh_ipv4, strict=False)
        if inventory.bootstrap_ipv4:
            try:
                host = ipaddress.ip_address(inventory.bootstrap_ipv4)
                if host in net4:
                    addresses.append(f"{host}/{net4.prefixlen}")
                else:
                    addresses.append(f"{next(net4.hosts())}/{net4.prefixlen}")
            except ValueError:
                addresses.append(f"{next(net4.hosts())}/{net4.prefixlen}")
        else:
            addresses.append(f"{next(net4.hosts())}/{net4.prefixlen}")

    mesh_ipv6 = network.get("mesh_ipv6")
    if isinstance(mesh_ipv6, str):
        net6 = ipaddress.ip_network(mesh_ipv6, strict=False)
        if inventory.bootstrap_ipv6:
            try:
                host = ipaddress.ip_address(inventory.bootstrap_ipv6)
                if host in net6:
                    addresses.append(f"{host}/{net6.prefixlen}")
                else:
                    addresses.append(f"{next(net6.hosts())}/{net6.prefixlen}")
            except ValueError:
                addresses.append(f"{next(net6.hosts())}/{net6.prefixlen}")
        else:
            addresses.append(f"{next(net6.hosts())}/{net6.prefixlen}")

    return addresses


def _missing_packages(inventory: SystemInventory, package_manager: str | None) -> list[str]:
    if package_manager is None:
        return []
    package_set = set(APT_PACKAGES if package_manager == "apt" else DNF_PACKAGES)
    missing: list[str] = []
    if not inventory.detected_binaries.get("ss") and "iproute2" in package_set:
        missing.append("iproute2")
    if not inventory.detected_binaries.get("wg"):
        for package in ("wireguard-tools", "wireguard"):
            if package in package_set:
                missing.append(package)
                break
    if not inventory.detected_binaries.get("curl") and "curl" in package_set:
        missing.append("curl")
    if "ca-certificates" in package_set:
        missing.append("ca-certificates")
    return sorted(set(missing))


def _join_credentials(config: dict[str, Any], nodes: list) -> tuple[str | None, str | None]:
    init = init_server_node(nodes)
    if init is None or not init.primary_ip:
        return None, None
    join_url = f"https://{init.primary_ip}:6443"
    cluster = config.get("cluster", {})
    token = cluster.get("join_token")
    if isinstance(token, str) and token.strip():
        return join_url, token.strip()
    ssh_user = cluster.get("ssh_user") if isinstance(cluster.get("ssh_user"), str) else None
    ok, detail = fetch_join_token_from_init(init, ssh_user=ssh_user)
    if ok:
        return join_url, detail.strip()
    return join_url, None


def _k3s_install_command_display(config: dict[str, Any], inventory: SystemInventory) -> str:
    nodes = parse_nodes(config)
    local_node = identify_local_node(nodes, inventory)
    all_nodes = nodes or []
    if local_node and all_nodes:
        join_url, join_token = _join_credentials(config, all_nodes)
        _, _, display = k3s_install_spec(
            config,
            local_node,
            all_nodes=all_nodes,
            join_url=join_url if local_node.role != "init-server" else None,
            join_token=join_token if local_node.role != "init-server" else None,
        )
        return display
    args = _k3s_install_args(config)
    arg_text = " ".join(args)
    return (
        "curl -sfL https://get.k3s.io | "
        "INSTALL_K3S_EXEC='server' sh -s - "
        f"{arg_text}".rstrip()
    )


def check_install_gate(
    *,
    config_path: str | Path | None = None,
    inventory: SystemInventory | None = None,
    require_sudo: bool = False,
) -> InstallGateResult:
    inventory = inventory or collect_inventory()
    resolved_path = Path(config_path) if config_path is not None else find_config()

    if resolved_path is None or not resolved_path.is_file():
        return InstallGateResult(
            ok=False,
            message=(
                "styx.yaml not found. Copy styx.yaml.example to styx.yaml and run "
                "`styxctl config validate` before installing."
            ),
            config={},
            config_path=None,
            config_status_value="INVALID",
            inventory=inventory,
            sysprep_status="BLOCKED",
            warnings=[],
            blocking=["styx.yaml is required for MVP2 install"],
        )

    config = load_config(resolved_path)
    issues = validate_config(config)
    status = config_status(issues)
    sysprep_status, warnings, blocking = evaluate_readiness(inventory)

    if status == "INVALID":
        return InstallGateResult(
            ok=False,
            message="Config is INVALID. Run `styxctl config validate` and fix errors before installing.",
            config=config,
            config_path=resolved_path,
            config_status_value=status,
            inventory=inventory,
            sysprep_status=sysprep_status,
            warnings=warnings,
            blocking=[f"{issue.path}: {issue.message}" for issue in issues if issue.level == "error"],
        )

    if sysprep_status == "BLOCKED":
        return InstallGateResult(
            ok=False,
            message=(
                "Sysprep status is BLOCKED. Run `styxctl sysprep check local`, then resolve conflicts with "
                "`styxctl sysprep safe local` before installing."
            ),
            config=config,
            config_path=resolved_path,
            config_status_value=status,
            inventory=inventory,
            sysprep_status=sysprep_status,
            warnings=warnings,
            blocking=blocking,
        )

    if require_sudo and not inventory.sudo_available:
        return InstallGateResult(
            ok=False,
            message="Non-interactive sudo is required for install. Configure sudo for the current user.",
            config=config,
            config_path=resolved_path,
            config_status_value=status,
            inventory=inventory,
            sysprep_status=sysprep_status,
            warnings=warnings,
            blocking=["non-interactive sudo is not available"],
        )

    return InstallGateResult(
        ok=True,
        message=None,
        config=config,
        config_path=resolved_path,
        config_status_value=status,
        inventory=inventory,
        sysprep_status=sysprep_status,
        warnings=warnings,
        blocking=blocking,
    )


def build_install_plan(
    gate: InstallGateResult,
    *,
    inventory: SystemInventory | None = None,
) -> InstallPlan:
    inventory = inventory or gate.inventory
    config = gate.config
    package_manager = detect_package_manager()
    wg0_before = capture_wg0_snapshot(inventory)
    steps: list[InstallStep] = []
    interface, port = _wireguard_settings(config)
    nodes = parse_nodes(config)
    local_node = identify_local_node(nodes, inventory)
    cluster_plan = build_cluster_plan(config, local_node=local_node) if nodes else None

    missing_packages = _missing_packages(inventory, package_manager)
    if missing_packages and package_manager == "apt":
        steps.append(
            InstallStep(
                name="system-packages",
                category="packages",
                action="install",
                status="pending",
                reason=f"Missing packages: {', '.join(missing_packages)}",
                command=[
                    "env",
                    "DEBIAN_FRONTEND=noninteractive",
                    "apt-get",
                    "install",
                    "-y",
                    "-qq",
                    *missing_packages,
                ],
                command_display=(
                    "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                    + " ".join(missing_packages)
                ),
            )
        )
    elif missing_packages and package_manager in {"dnf", "yum"}:
        steps.append(
            InstallStep(
                name="system-packages",
                category="packages",
                action="install",
                status="pending",
                reason=f"Missing packages: {', '.join(missing_packages)}",
                command=[package_manager, "install", "-y", *missing_packages],
                command_display=f"sudo {package_manager} install -y {' '.join(missing_packages)}",
            )
        )
    elif missing_packages:
        steps.append(
            InstallStep(
                name="system-packages",
                category="packages",
                action="install",
                status="deferred",
                reason=f"Packages needed ({', '.join(missing_packages)}) but no supported package manager found",
            )
        )
    else:
        steps.append(
            InstallStep(
                name="system-packages",
                category="packages",
                action="verify",
                status="skipped",
                reason="Required system packages already present",
            )
        )

    steps.append(
        InstallStep(
            name="wireguard-module",
            category="kernel",
            action="load",
            status="pending",
            reason="Ensure WireGuard kernel module is loaded",
            command=["modprobe", "wireguard"],
            command_display="sudo modprobe wireguard",
            requires_sudo=True,
        )
    )

    if inventory.detected_binaries.get("k3s"):
        steps.append(
            InstallStep(
                name="k3s",
                category="platform",
                action="verify",
                status="skipped",
                reason=f"k3s already present at {inventory.detected_binaries['k3s']}",
            )
        )
    elif local_node and local_node.role != "init-server":
        join_url, join_token = _join_credentials(config, nodes)
        if not join_token:
            steps.append(
                InstallStep(
                    name="k3s",
                    category="platform",
                    action="join",
                    status="deferred",
                    reason=(
                        f"Node {local_node.name} ({local_node.role}) needs a join token. "
                        "Run `styxctl install cluster --yes` from the init node first, "
                        "or set cluster.join_token in styx.yaml."
                    ),
                )
            )
        else:
            _, _, display = k3s_install_spec(
                config,
                local_node,
                all_nodes=nodes,
                join_url=join_url,
                join_token=join_token,
            )
            steps.append(
                InstallStep(
                    name="k3s",
                    category="platform",
                    action="join",
                    status="pending",
                    reason=f"Join {local_node.name} as {local_node.role} using current node IPs",
                    command=["curl", "-sfL", "https://get.k3s.io"],
                    command_display=display,
                )
            )
    else:
        steps.append(
            InstallStep(
                name="k3s",
                category="platform",
                action="install",
                status="pending",
                reason=(
                    f"Install k3s {'init-server' if local_node and local_node.role == 'init-server' else 'server'} "
                    "with Styx dual-stack CIDRs and node IPs from styx.yaml"
                ),
                command=["curl", "-sfL", "https://get.k3s.io"],
                command_display=_k3s_install_command_display(config, inventory),
            )
        )

    if nodes:
        steps.append(
            InstallStep(
                name="k3s-cluster",
                category="platform",
                action="plan",
                status="pending",
                reason=f"Cluster has {len(nodes)} nodes; run `styxctl install cluster --yes` to join remote nodes",
                command_display="styxctl install cluster --yes",
            )
        )

    styx_conf = STYX_WG_DIR / f"{interface}.conf"
    if interface in inventory.interface_names or interface in inventory.wireguard_interfaces:
        steps.append(
            InstallStep(
                name="styx-wireguard",
                category="wireguard",
                action="verify",
                status="skipped",
                reason=f"{interface} interface already present",
            )
        )
    else:
        addresses = _wireguard_addresses(config, inventory)
        steps.append(
            InstallStep(
                name="styx-wireguard",
                category="wireguard",
                action="configure",
                status="pending",
                reason=f"Create {styx_conf} and bring up {interface} on port {port}/udp",
                command=["wg-quick", "up", interface],
                command_display=(
                    f"write {styx_conf} with Address={', '.join(addresses)} "
                    f"ListenPort={port}; sudo wg-quick up {interface}"
                ),
            )
        )

    steps.append(
        InstallStep(
            name="firewall",
            category="firewall",
            action="allow",
            status="pending",
            reason=f"Allow {port}/udp for Styx WireGuard and k3s service ports",
            command_display=(
                f"allow {port}/udp (ufw/nft/firewalld minimal rule if backend detected)"
            ),
        )
    )

    return InstallPlan(
        hostname=inventory.hostname,
        config_path=str(gate.config_path) if gate.config_path else None,
        config_status=gate.config_status_value,
        sysprep_status=gate.sysprep_status,
        warnings=gate.warnings,
        blocking=gate.blocking,
        wg0_before=wg0_before,
        local_node=local_node.name if local_node else None,
        cluster_plan=cluster_plan,
        steps=steps,
    )


def _run_pipeline(
    left: list[str],
    right: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: float = 900.0,
) -> RunResult:
    left_exec = shutil.which(left[0])
    right_exec = shutil.which(right[0])
    if not left_exec or not right_exec:
        return False, "pipeline command not found"

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
            env={**os.environ, **(env or {})},
        )
        if left_proc.stdout is not None:
            left_proc.stdout.close()
        stdout, stderr = right_proc.communicate(timeout=timeout)
        left_proc.wait(timeout=1)
        if right_proc.returncode == 0:
            return True, (stdout or stderr or "ok").strip()
        return False, (stderr or stdout or f"exit code {right_proc.returncode}").strip()
    except subprocess.TimeoutExpired:
        return False, f"timed out after {timeout} seconds"
    except OSError as exc:
        return False, str(exc)


def _apt_install(
    packages: list[str],
    inventory: SystemInventory,
    runner: Callable[..., RunResult] | None = None,
) -> RunResult:
    update_ok, update_detail = _run_mutating(
        ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update", "-qq"],
        use_sudo=True,
        sudo_available=inventory.sudo_available,
        timeout=300.0,
    )
    if not update_ok:
        return False, update_detail

    return _run_mutating(
        ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-qq", *packages],
        use_sudo=True,
        sudo_available=inventory.sudo_available,
        timeout=600.0,
    )


def _write_styx_wireguard_config(
    config: dict[str, Any],
    inventory: SystemInventory,
    *,
    interface: str,
    port: int,
) -> RunResult:
    addresses = _wireguard_addresses(config, inventory)
    if not addresses:
        return False, "could not derive WireGuard addresses from styx.yaml"

    genkey = safe_run("wg_genkey", ["wg", "genkey"], timeout=5.0)
    if genkey.returncode != 0 or not genkey.stdout.strip():
        private_key = secrets.token_hex(32)
    else:
        private_key = genkey.stdout.strip()

    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {', '.join(addresses)}",
        f"ListenPort = {port}",
        "",
    ]
    content = "\n".join(lines)
    styx_conf = STYX_WG_DIR / f"{interface}.conf"
    temp_path = Path("/tmp") / f"styx-{interface}.conf"

    try:
        temp_path.write_text(content, encoding="utf-8")
    except OSError as exc:
        return False, str(exc)

    ok, detail = _run_mutating(
        ["mkdir", "-p", str(STYX_WG_DIR)],
        use_sudo=True,
        sudo_available=inventory.sudo_available,
    )
    if not ok:
        return False, detail

    ok, detail = _run_mutating(
        ["cp", str(temp_path), str(styx_conf)],
        use_sudo=True,
        sudo_available=inventory.sudo_available,
    )
    if not ok:
        return False, detail

    ok, detail = _run_mutating(
        ["chmod", "600", str(styx_conf)],
        use_sudo=True,
        sudo_available=inventory.sudo_available,
    )
    if not ok:
        return False, detail

    try:
        temp_path.unlink(missing_ok=True)
    except OSError:
        pass

    return True, f"wrote {styx_conf}"


def _apply_firewall_allowance(
    port: int,
    inventory: SystemInventory,
) -> RunResult:
    binaries = inventory.firewall_backend.get("binaries", {})
    services = inventory.firewall_backend.get("services", {})

    ufw_active = (services.get("ufw", {}).get("active") or "").lower() == "active"
    if binaries.get("ufw") and ufw_active:
        return _run_mutating(
            ["ufw", "allow", f"{port}/udp"],
            use_sudo=True,
            sudo_available=inventory.sudo_available,
        )

    firewalld_active = (services.get("firewalld", {}).get("active") or "").lower() == "active"
    if binaries.get("firewall-cmd") and firewalld_active:
        return _run_mutating(
            ["firewall-cmd", "--permanent", "--add-port", f"{port}/udp"],
            use_sudo=True,
            sudo_available=inventory.sudo_available,
        )

    if binaries.get("nft"):
        return _run_mutating(
            [
                "nft",
                "add",
                "rule",
                "inet",
                "filter",
                "input",
                "udp",
                "dport",
                str(port),
                "accept",
            ],
            use_sudo=True,
            sudo_available=inventory.sudo_available,
        )

    return True, "no active firewall backend detected; skipped explicit rule"


def _execute_step(
    step: InstallStep,
    *,
    config: dict[str, Any],
    inventory: SystemInventory,
) -> InstallStep:
    if step.status != "pending":
        return step

    interface, port = _wireguard_settings(config)

    if step.name == "system-packages":
        package_manager = detect_package_manager()
        packages = _missing_packages(inventory, package_manager)
        if not packages:
            step.status = "skipped"
            step.detail = "packages already present"
            return step
        if package_manager == "apt":
            ok, detail = _apt_install(packages, inventory)
        elif package_manager in {"dnf", "yum"}:
            ok, detail = _run_mutating(
                [package_manager, "install", "-y", *packages],
                use_sudo=True,
                sudo_available=inventory.sudo_available,
                timeout=600.0,
            )
        else:
            step.status = "failed"
            step.detail = "unsupported package manager"
            return step
    elif step.name == "wireguard-module":
        ok, detail = _run_mutating(
            ["modprobe", "wireguard"],
            use_sudo=True,
            sudo_available=inventory.sudo_available,
        )
    elif step.name == "k3s":
        nodes = parse_nodes(config)
        local_node = identify_local_node(nodes, inventory)
        if local_node and nodes:
            join_url, join_token = _join_credentials(config, nodes)
            env, args, _ = k3s_install_spec(
                config,
                local_node,
                all_nodes=nodes,
                join_url=join_url if local_node.role != "init-server" else None,
                join_token=join_token if local_node.role != "init-server" else None,
            )
        else:
            env = {"INSTALL_K3S_EXEC": "server"}
            args = _k3s_install_args(config)
        ok, detail = _run_pipeline(
            ["curl", "-sfL", "https://get.k3s.io"],
            ["sh", "-s", "-", *args],
            env=env,
        )
    elif step.name == "k3s-cluster":
        step.status = "skipped"
        step.detail = "cluster orchestration is handled by `styxctl install cluster`"
        return step
    elif step.name == "styx-wireguard":
        ok, detail = _write_styx_wireguard_config(
            config,
            inventory,
            interface=interface,
            port=port,
        )
        if ok:
            up_ok, up_detail = _run_mutating(
                ["wg-quick", "up", interface],
                use_sudo=True,
                sudo_available=inventory.sudo_available,
            )
            ok, detail = up_ok, f"{detail}; {up_detail}"
    elif step.name == "firewall":
        ok, detail = _apply_firewall_allowance(port, inventory)
    else:
        step.status = "skipped"
        step.detail = "no executor"
        return step

    step.status = "installed" if ok else "failed"
    step.detail = detail
    return step


def apply_install_plan(
    plan: InstallPlan,
    *,
    config: dict[str, Any],
    inventory: SystemInventory | None = None,
    dry_run: bool = False,
) -> InstallPlan:
    inventory = inventory or collect_inventory()
    if dry_run:
        return plan

    updated_steps: list[InstallStep] = []
    for step in plan.steps:
        updated_steps.append(_execute_step(step, config=config, inventory=inventory))

    wg0_after = capture_wg0_snapshot(collect_inventory())
    preserved, reason = verify_wg0_preserved(plan.wg0_before, wg0_after)
    if not preserved:
        updated_steps.append(
            InstallStep(
                name="wg0-preservation",
                category="safety",
                action="verify",
                status="failed",
                reason=reason,
                detail="install rolled back logically; investigate wg0 before retrying",
            )
        )

    return InstallPlan(
        hostname=plan.hostname,
        config_path=plan.config_path,
        config_status=plan.config_status,
        sysprep_status=plan.sysprep_status,
        warnings=plan.warnings,
        blocking=plan.blocking,
        wg0_before=plan.wg0_before,
        steps=updated_steps,
    )


def _service_active(inventory: SystemInventory, service_key: str) -> bool:
    service = inventory.detected_services.get(service_key, {})
    active = (service.get("active") or "").lower()
    return active in {"active", "activating", "reloading"}


def _k3s_version(inventory: SystemInventory) -> str | None:
    if not inventory.detected_binaries.get("k3s"):
        return None
    result = safe_run("k3s_version", ["k3s", "--version"], timeout=5.0)
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip().splitlines()[0]
    return None


def _styx_port_listening(inventory: SystemInventory, port: int, interface: str) -> bool:
    if interface in inventory.wireguard_interfaces:
        result = safe_run("wg_show_interface", ["wg", "show", interface], timeout=5.0)
        if result.returncode == 0 and "listening port" in result.stdout.lower():
            return str(port) in result.stdout

    for conflict in inventory.ports.conflicts:
        if conflict.port == port and conflict.protocol == "udp":
            process = (conflict.process_name or "").lower()
            if any(token in process for token in ("wg", "wireguard", interface.lower())):
                return True
    return False


def assess_install_health(
    *,
    config_path: str | Path | None = None,
    inventory: SystemInventory | None = None,
    wg0_before: Wg0Snapshot | None = None,
) -> InstallHealth:
    inventory = inventory or collect_inventory()
    resolved_path = Path(config_path) if config_path is not None else find_config()
    config = load_config(resolved_path) if resolved_path else {}
    issues = validate_config(config)
    status = config_status(issues)
    interface, port = _wireguard_settings(config)

    wg0_after = capture_wg0_snapshot(inventory)
    if wg0_before is not None:
        wg0_preserved, wg0_issue = verify_wg0_preserved(wg0_before, wg0_after)
    else:
        wg0_preserved, wg0_issue = True, None

    critical_conflicts = [
        conflict
        for conflict in inventory.ports.conflicts
        if conflict.port in CRITICAL_PORTS and not (conflict.port == port and conflict.protocol == "udp")
    ]
    critical_ports_clear = not critical_conflicts

    health_issues: list[str] = []
    warnings: list[str] = list(assess_install_health_warnings(inventory))

    k3s_installed = bool(inventory.detected_binaries.get("k3s"))
    k3s_active = _service_active(inventory, "k3s")
    kubectl_available = bool(inventory.detected_binaries.get("kubectl"))
    wg_binary = bool(inventory.detected_binaries.get("wg"))
    styx_interface_up = interface in inventory.interface_names or interface in inventory.wireguard_interfaces
    styx_port_listening = _styx_port_listening(inventory, port, interface)

    if status == "INVALID":
        health_issues.append("config is INVALID")
    if not k3s_installed:
        health_issues.append("k3s binary is not installed")
    if k3s_installed and not k3s_active:
        health_issues.append("k3s.service is not active")
    if not kubectl_available:
        health_issues.append("kubectl is not available")
    if not wg_binary:
        health_issues.append("wg binary is not available")
    if not styx_interface_up:
        health_issues.append(f"{interface} interface is not up")
    if not styx_port_listening:
        health_issues.append(f"{interface} is not listening on {port}/udp")
    if not wg0_preserved:
        health_issues.append(wg0_issue or "wg0 was modified")
    if not critical_ports_clear:
        health_issues.append("critical Styx ports 47800-47808 have conflicts")

    cluster_nodes = parse_nodes(config)
    local_node = identify_local_node(cluster_nodes, inventory)
    healthy = not health_issues
    return InstallHealth(
        healthy=healthy,
        k3s_installed=k3s_installed,
        k3s_active=k3s_active,
        k3s_version=_k3s_version(inventory),
        kubectl_available=kubectl_available,
        wg_binary=wg_binary,
        styx_interface_up=styx_interface_up,
        styx_port_listening=styx_port_listening,
        wg0_preserved=wg0_preserved,
        config_status=status,
        config_path=str(resolved_path) if resolved_path else None,
        critical_ports_clear=critical_ports_clear,
        cluster_healthy=None,
        cluster_node_count=len(cluster_nodes),
        local_node=local_node.name if local_node else None,
        issues=health_issues,
        warnings=warnings,
    )


def assess_install_health_warnings(inventory: SystemInventory) -> list[str]:
    warnings: list[str] = []
    lowered_time = inventory.time_sync_status.lower()
    if "ntpsynchronized=no" in lowered_time or "system clock synchronized: no" in lowered_time:
        warnings.append("time synchronization appears disabled or unsynchronized")
    return warnings


def run_install_doctor(
    *,
    config_path: str | Path | None = None,
    inventory: SystemInventory | None = None,
) -> InstallHealth:
    return assess_install_health(config_path=config_path, inventory=inventory)


def build_install_report(
    *,
    command: str,
    plan: InstallPlan,
    gate: InstallGateResult,
    dry_run: bool,
    health: InstallHealth | None = None,
    pre_inventory: SystemInventory | None = None,
    post_inventory: SystemInventory | None = None,
) -> dict[str, Any]:
    failed_steps = [step for step in plan.steps if step.status == "failed"]
    if gate.ok and not failed_steps:
        if dry_run:
            status = "DRY_RUN"
        elif health and health.healthy:
            status = "INSTALLED"
        elif health:
            status = "INSTALLED_WITH_ISSUES"
        else:
            status = "INSTALLED"
    else:
        status = "FAILED" if not gate.ok else "FAILED"

    return {
        "tool": "styxctl",
        "report_type": "install",
        "command": command,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hostname": plan.hostname,
        "status": status,
        "dry_run": dry_run,
        "gate": gate.to_dict(),
        "plan": plan.to_dict(),
        "health": health.to_dict() if health else None,
        "blocking": gate.blocking,
        "warnings": gate.warnings,
        "issues": health.issues if health else [],
        "pre_inventory": pre_inventory.to_dict() if pre_inventory else None,
        "post_inventory": post_inventory.to_dict() if post_inventory else None,
    }


def run_install_local(
    *,
    dry_run: bool = False,
    yes: bool = False,
    config_path: str | Path | None = None,
) -> tuple[dict[str, Any], int]:
    pre_inventory = collect_inventory()
    gate = check_install_gate(
        config_path=config_path,
        inventory=pre_inventory,
        require_sudo=not dry_run,
    )
    plan = build_install_plan(gate) if gate.ok else InstallPlan(
        hostname=pre_inventory.hostname,
        config_path=str(gate.config_path) if gate.config_path else None,
        config_status=gate.config_status_value,
        sysprep_status=gate.sysprep_status,
        warnings=gate.warnings,
        blocking=gate.blocking,
        wg0_before=capture_wg0_snapshot(pre_inventory),
        steps=[],
    )

    if not gate.ok:
        report = build_install_report(
            command="styxctl install local",
            plan=plan,
            gate=gate,
            dry_run=dry_run,
            pre_inventory=pre_inventory,
        )
        return report, 1

    pending = [step for step in plan.steps if step.status == "pending"]
    if not dry_run and pending and not yes:
        report = build_install_report(
            command="styxctl install local",
            plan=plan,
            gate=gate,
            dry_run=True,
            pre_inventory=pre_inventory,
        )
        report["status"] = "CONFIRMATION_REQUIRED"
        report["pending_count"] = len(pending)
        return report, 0

    applied_plan = apply_install_plan(
        plan,
        config=gate.config,
        inventory=pre_inventory,
        dry_run=dry_run,
    )
    post_inventory = collect_inventory() if not dry_run else pre_inventory
    health = assess_install_health(
        config_path=gate.config_path,
        inventory=post_inventory,
        wg0_before=plan.wg0_before,
    ) if not dry_run else None

    report = build_install_report(
        command="styxctl install local" + (" --dry-run" if dry_run else ""),
        plan=applied_plan,
        gate=gate,
        dry_run=dry_run,
        health=health,
        pre_inventory=pre_inventory,
        post_inventory=post_inventory,
    )

    if dry_run:
        return report, 0
    if any(step.status == "failed" for step in applied_plan.steps):
        return report, 1
    if health and not health.healthy:
        return report, 1
    return report, 0


def run_install_plan_preview(*, config_path: str | Path | None = None) -> tuple[dict[str, Any], int]:
    pre_inventory = collect_inventory()
    gate = check_install_gate(config_path=config_path, inventory=pre_inventory, require_sudo=False)
    plan = build_install_plan(gate) if gate.ok else InstallPlan(
        hostname=pre_inventory.hostname,
        config_path=str(gate.config_path) if gate.config_path else None,
        config_status=gate.config_status_value,
        sysprep_status=gate.sysprep_status,
        warnings=gate.warnings,
        blocking=gate.blocking,
        wg0_before=capture_wg0_snapshot(pre_inventory),
        steps=[],
    )
    report = build_install_report(
        command="styxctl install plan local --dry-run",
        plan=plan,
        gate=gate,
        dry_run=True,
        pre_inventory=pre_inventory,
    )
    return report, 0 if gate.ok else 1


def check_cluster_gate(
    *,
    config_path: str | Path | None = None,
    require_sudo: bool = False,
) -> InstallGateResult:
    gate = check_install_gate(config_path=config_path, require_sudo=require_sudo)
    if not gate.ok:
        return gate

    nodes = parse_nodes(gate.config)
    node_errors = validate_nodes(nodes)
    if not nodes:
        return InstallGateResult(
            ok=False,
            message="No cluster nodes defined in styx.yaml. Add a nodes list with IPs and roles.",
            config=gate.config,
            config_path=gate.config_path,
            config_status_value=gate.config_status_value,
            inventory=gate.inventory,
            sysprep_status=gate.sysprep_status,
            warnings=gate.warnings,
            blocking=["nodes list is empty"],
        )
    if node_errors:
        return InstallGateResult(
            ok=False,
            message="Cluster node configuration is invalid.",
            config=gate.config,
            config_path=gate.config_path,
            config_status_value="INVALID",
            inventory=gate.inventory,
            sysprep_status=gate.sysprep_status,
            warnings=gate.warnings,
            blocking=node_errors,
        )
    return gate


def run_install_cluster(
    *,
    dry_run: bool = False,
    yes: bool = False,
    config_path: str | Path | None = None,
    runner: Callable[[str, str], RunResult] | None = None,
) -> tuple[dict[str, Any], int]:
    pre_inventory = collect_inventory()
    gate = check_cluster_gate(
        config_path=config_path,
        require_sudo=not dry_run,
    )
    nodes = parse_nodes(gate.config) if gate.ok else []
    local_node = identify_local_node(nodes, pre_inventory) if nodes else None
    cluster_plan = build_cluster_plan(gate.config, local_node=local_node) if gate.ok else ClusterPlan(init_node="unknown")

    base_plan = InstallPlan(
        hostname=pre_inventory.hostname,
        config_path=str(gate.config_path) if gate.config_path else None,
        config_status=gate.config_status_value,
        sysprep_status=gate.sysprep_status,
        warnings=gate.warnings,
        blocking=gate.blocking,
        wg0_before=capture_wg0_snapshot(pre_inventory),
        local_node=local_node.name if local_node else None,
        cluster_plan=cluster_plan,
        steps=[],
    )

    if not gate.ok:
        report = build_install_report(
            command="styxctl install cluster",
            plan=base_plan,
            gate=gate,
            dry_run=dry_run,
            pre_inventory=pre_inventory,
        )
        report["status"] = "FAILED"
        return report, 1

    if dry_run:
        report = build_install_report(
            command="styxctl install cluster --dry-run",
            plan=base_plan,
            gate=gate,
            dry_run=True,
            pre_inventory=pre_inventory,
        )
        report["cluster"] = cluster_plan.to_dict()
        return report, 0

    pending = [item for item in cluster_plan.nodes if not item.local_execution]
    if pending and not yes:
        report = build_install_report(
            command="styxctl install cluster",
            plan=base_plan,
            gate=gate,
            dry_run=True,
            pre_inventory=pre_inventory,
        )
        report["status"] = "CONFIRMATION_REQUIRED"
        report["pending_count"] = len(pending)
        report["cluster"] = cluster_plan.to_dict()
        return report, 0

    ssh_user = gate.config.get("cluster", {}).get("ssh_user")
    join_url: str | None = None
    join_token: str | None = None
    ssh_runner = runner or _run_ssh_command

    for node_plan in cluster_plan.nodes:
        if node_plan.local_execution and local_node:
            env, args, _ = k3s_install_spec(
                gate.config,
                local_node,
                all_nodes=nodes,
                join_url=join_url,
                join_token=join_token,
            )
            ok, detail = _run_pipeline(
                ["curl", "-sfL", "https://get.k3s.io"],
                ["sh", "-s", "-", *args],
                env=env,
            )
            node_plan.status = "installed" if ok else "failed"
            node_plan.detail = detail
        else:
            if node_plan.role != "init-server" and not join_token:
                init = init_server_node(nodes)
                if init:
                    token_ok, token_detail = fetch_join_token_from_init(init, ssh_user=ssh_user, runner=ssh_runner)
                    if token_ok:
                        join_token = token_detail.strip()
                        join_url = f"https://{init.primary_ip}:6443"
                        env, args, _ = k3s_install_spec(
                            gate.config,
                            node_plan.node,
                            all_nodes=nodes,
                            join_url=join_url,
                            join_token=join_token,
                        )
                        node_plan.k3s_env = env
                        node_plan.k3s_args = args
            apply_cluster_node_plan(node_plan, ssh_user=ssh_user, runner=ssh_runner)

        if node_plan.role == "init-server" and node_plan.status == "installed":
            init = init_server_node(nodes)
            if init:
                token_ok, token_detail = fetch_join_token_from_init(init, ssh_user=ssh_user, runner=ssh_runner)
                if token_ok:
                    join_token = token_detail.strip()
                    join_url = f"https://{init.primary_ip}:6443"

    cluster_health = assess_cluster_nodes(gate.config, ssh_user=ssh_user, runner=ssh_runner)
    report = build_install_report(
        command="styxctl install cluster",
        plan=base_plan,
        gate=gate,
        dry_run=False,
        pre_inventory=pre_inventory,
        post_inventory=collect_inventory(),
    )
    report["cluster"] = cluster_plan.to_dict()
    report["cluster_health"] = cluster_health
    report["status"] = "INSTALLED" if cluster_health.get("healthy") else "INSTALLED_WITH_ISSUES"

    if any(item.status == "failed" for item in cluster_plan.nodes):
        return report, 1
    if not cluster_health.get("healthy"):
        return report, 1
    return report, 0


def run_cluster_doctor(*, config_path: str | Path | None = None) -> dict[str, Any]:
    config = load_config(config_path) if config_path else load_config(find_config())
    ssh_user = config.get("cluster", {}).get("ssh_user") if isinstance(config.get("cluster"), dict) else None
    return assess_cluster_nodes(config, ssh_user=ssh_user)
