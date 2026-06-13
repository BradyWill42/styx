"""Safe local inventory collection for Styx sysprep.

All collection is read-only. Failed commands are recorded instead of raising.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import getpass
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
from typing import Iterable

from .ports import PortScanResult, check_reserved_ports


@dataclass(slots=True)
class CommandResult:
    name: str
    command: list[str]
    available: bool
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class SystemInventory:
    generated_at: str
    hostname: str
    fqdn: str
    os_version: str
    architecture: str
    kernel_version: str
    boot_time: str | None
    current_user: str
    sudo_available: bool
    primary_lan_ip: str | None
    bootstrap_ipv4: str | None
    bootstrap_ipv6: str | None
    default_route: str
    dns_resolvers: list[str]
    time_sync_status: str
    disk_usage: str
    memory_swap: str
    mounted_filesystems: str
    network_interfaces: list[str]
    interface_names: list[str]
    wireguard_interfaces: list[str]
    ports: PortScanResult
    detected_binaries: dict[str, str | None]
    detected_services: dict[str, dict[str, str | None]]
    detected_artifacts: dict[str, list[str]]
    cni_interfaces: list[str]
    firewall_backend: dict[str, object]
    commands: dict[str, CommandResult] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["ports"] = self.ports.to_dict()
        data["commands"] = {name: result.to_dict() for name, result in self.commands.items()}
        return data


def safe_run(name: str, command: list[str], timeout: float = 8.0) -> CommandResult:
    """Run a read-only command safely and record all failure modes."""
    def _result(**kwargs: object) -> CommandResult:
        defaults = {"available": True, "returncode": None, "stdout": "", "stderr": "", "timed_out": False, "error": None}
        defaults.update(kwargs)
        return CommandResult(name=name, command=command, **defaults)

    executable = shutil.which(command[0])
    if executable is None:
        return _result(available=False, returncode=None, error=f"command not found: {command[0]}")

    resolved = [executable, *command[1:]]
    try:
        completed = subprocess.run(
            resolved,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode(errors="replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode(errors="replace")
        return _result(
            returncode=None,
            stdout=stdout or "",
            stderr=stderr or "",
            timed_out=True,
            error=f"timed out after {timeout} seconds",
        )
    except OSError as exc:
        return _result(returncode=None, error=str(exc))

    return _result(
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        error=None if completed.returncode == 0 else "nonzero exit code",
    )


def _read_text(path: str | Path) -> str:
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return ""


def parse_os_release(text: str) -> str:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, raw = line.split("=", 1)
        values[key] = raw.strip().strip('"')
    pretty = values.get("PRETTY_NAME")
    if pretty:
        return pretty
    name = values.get("NAME")
    version = values.get("VERSION")
    if name and version:
        return f"{name} {version}"
    return platform.platform()


def boot_time_from_proc_stat(text: str) -> str | None:
    for line in text.splitlines():
        if line.startswith("btime "):
            try:
                timestamp = int(line.split()[1])
            except (IndexError, ValueError):
                return None
            return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    return None


def parse_nameservers(resolv_conf: str) -> list[str]:
    resolvers: list[str] = []
    for line in resolv_conf.splitlines():
        stripped = line.strip()
        if not stripped.startswith("nameserver "):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            resolvers.append(parts[1])
    return resolvers


def parse_ip_route_src(output: str) -> str | None:
    match = re.search(r"\bsrc\s+(\S+)", output)
    return match.group(1) if match else None


def parse_ip_br_addr(output: str) -> tuple[list[str], list[str]]:
    lines = [line.rstrip() for line in output.splitlines() if line.strip()]
    names: list[str] = []
    for line in lines:
        first = line.split(maxsplit=1)[0]
        names.append(first.split("@", 1)[0])
    return lines, names


def parse_wg_interfaces(command: CommandResult, interface_names: Iterable[str]) -> list[str]:
    if command.available and command.returncode == 0 and command.stdout.strip():
        return command.stdout.split()
    return [name for name in interface_names if name == "wg0" or name.lower().startswith("wg") or name == "Styx"]


def detect_binaries(names: Iterable[str]) -> dict[str, str | None]:
    return {name: shutil.which(name) for name in names}


def detect_service(service_name: str, commands: dict[str, CommandResult]) -> dict[str, str | None]:
    def _state(kind: str) -> str | None:
        result = safe_run(f"systemctl_is_{kind}_{service_name}", ["systemctl", f"is-{kind}", service_name], timeout=3.0)
        commands[result.name] = result
        value = result.stdout.strip()
        return value or ("missing" if result.returncode not in (0, None) else None)

    return {"active": _state("active"), "enabled": _state("enabled")}


def _existing(paths: Iterable[str], *, glob: bool = False) -> list[str]:
    found: list[str] = []
    for raw in paths:
        candidates = sorted(Path("/").glob(raw.lstrip("/"))) if glob else [Path(raw)]
        for path in candidates:
            try:
                if path.exists():
                    found.append(str(path))
            except OSError:
                continue
    return found


ARTIFACT_PATHS = {
    "old_k3s_files": (
        "/usr/local/bin/k3s",
        "/etc/systemd/system/k3s.service",
        "/etc/systemd/system/k3s-agent.service",
        "/lib/systemd/system/k3s.service",
        "/lib/systemd/system/k3s-agent.service",
        "/var/lib/rancher/k3s",
        "/etc/rancher/k3s",
        "/run/k3s",
    ),
    "old_kubelet_state": ("/var/lib/kubelet",),
    "old_cni_configs": ("/etc/cni", "/var/lib/cni"),
    "old_flannel_state": ("/run/flannel",),
}
INTERFACE_ARTIFACTS = {
    "old_cni_interfaces": ("cni0",),
    "old_flannel_interfaces": ("flannel.1", "flannel-v6.1"),
    "old_styx_interface_exact": ("Styx",),
}
CNI_INTERFACE_NAMES = frozenset({"cni0", "flannel.1", "flannel-v6.1"})
SERVICE_UNITS = {
    "k3s": "k3s.service",
    "k3s_agent": "k3s-agent.service",
    "containerd": "containerd.service",
    "docker": "docker.service",
    "wazuh_agent": "wazuh-agent.service",
    "wazuh_manager": "wazuh-manager.service",
    "watchdog": "watchdog.service",
    "styx": "styx.service",
}
BINARY_NAMES = (
    "k3s", "kubectl", "containerd", "docker", "wg",
    "wazuh-control", "wazuh-agentd", "watchdog", "nft", "iptables", "ip6tables", "ss",
)


def detect_artifacts(interface_names: Iterable[str]) -> dict[str, list[str]]:
    interface_set = set(interface_names)
    artifacts = {name: _existing(paths) for name, paths in ARTIFACT_PATHS.items()}
    artifacts.update(
        {name: [item for item in names if item in interface_set] for name, names in INTERFACE_ARTIFACTS.items()}
    )
    artifacts["old_temporary_styx_files"] = _existing(["/tmp/styx*", "/var/tmp/styx*"], glob=True)
    return artifacts


def detect_firewall_backend(commands: dict[str, CommandResult]) -> dict[str, object]:
    binaries = detect_binaries(["nft", "iptables", "ip6tables", "ufw", "firewall-cmd"])
    services = {
        "ufw": detect_service("ufw.service", commands),
        "firewalld": detect_service("firewalld.service", commands),
    }
    preferred = "unknown"
    if binaries.get("nft"):
        preferred = "nftables available"
    elif binaries.get("iptables"):
        preferred = "iptables available"
    return {"preferred": preferred, "binaries": binaries, "services": services}


def collect_inventory() -> SystemInventory:
    commands: dict[str, CommandResult] = {}

    for name, command, timeout in (
        ("hostname_short", ["hostname", "-s"], 3.0),
        ("hostname_fqdn", ["hostname", "-f"], 3.0),
        ("uname_all", ["uname", "-a"], 3.0),
        ("ip_br_addr", ["ip", "-br", "addr"], 5.0),
        ("ip_br_link", ["ip", "-br", "link"], 5.0),
        ("ip_route", ["ip", "route"], 5.0),
        ("ip_route_default", ["ip", "route", "show", "default"], 5.0),
        ("ip_route_get_ipv4", ["ip", "-4", "route", "get", "1.1.1.1"], 5.0),
        ("ip_route_get_ipv6", ["ip", "-6", "route", "get", "2606:4700:4700::1111"], 5.0),
        ("ip6_route", ["ip", "-6", "route"], 5.0),
        ("resolvectl_status", ["resolvectl", "status"], 5.0),
        ("timedatectl", ["timedatectl"], 5.0),
        ("df_h", ["df", "-h"], 8.0),
        ("free_h", ["free", "-h"], 5.0),
        ("lsblk", ["lsblk"], 8.0),
        ("findmnt", ["findmnt"], 8.0),
        ("ss_tulpen", ["ss", "-tulpen"], 8.0),
        ("systemctl_services", ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain"], 8.0),
        ("wg_show", ["wg", "show"], 5.0),
        ("wg_show_interfaces", ["wg", "show", "interfaces"], 5.0),
        ("sudo_noninteractive", ["sudo", "-n", "true"], 3.0),
    ):
        commands[name] = safe_run(name, command, timeout=timeout)

    hostname_cmd = commands["hostname_short"]
    fqdn_cmd = commands["hostname_fqdn"]
    hostname = hostname_cmd.stdout.strip() or socket.gethostname().split(".", 1)[0]
    fqdn = fqdn_cmd.stdout.strip() or socket.getfqdn()

    os_release = _read_text("/etc/os-release")
    os_version = parse_os_release(os_release)
    boot_time = boot_time_from_proc_stat(_read_text("/proc/stat"))
    resolvers = parse_nameservers(_read_text("/etc/resolv.conf"))

    network_lines, interface_names = parse_ip_br_addr(commands["ip_br_addr"].stdout)
    if not interface_names:
        _, interface_names = parse_ip_br_addr(commands["ip_br_link"].stdout)

    bootstrap_ipv4 = parse_ip_route_src(commands["ip_route_get_ipv4"].stdout)
    bootstrap_ipv6 = parse_ip_route_src(commands["ip_route_get_ipv6"].stdout)
    primary_lan_ip = bootstrap_ipv4 or bootstrap_ipv6

    wireguard_interfaces = parse_wg_interfaces(commands["wg_show_interfaces"], interface_names)
    port_scan = check_reserved_ports()

    detected_binaries = detect_binaries(BINARY_NAMES)

    detected_services = {name: detect_service(service, commands) for name, service in SERVICE_UNITS.items()}

    detected_artifacts = detect_artifacts(interface_names)
    cni_interfaces = [name for name in interface_names if name in CNI_INTERFACE_NAMES]
    firewall_backend = detect_firewall_backend(commands)

    time_sync_status = commands["timedatectl"].stdout.strip() or commands["timedatectl"].stderr.strip() or "unknown"

    return SystemInventory(
        generated_at=datetime.now(timezone.utc).isoformat(),
        hostname=hostname,
        fqdn=fqdn,
        os_version=os_version,
        architecture=platform.machine(),
        kernel_version=platform.release(),
        boot_time=boot_time,
        current_user=getpass.getuser(),
        sudo_available=commands["sudo_noninteractive"].returncode == 0,
        primary_lan_ip=primary_lan_ip,
        bootstrap_ipv4=bootstrap_ipv4,
        bootstrap_ipv6=bootstrap_ipv6,
        default_route=commands["ip_route_default"].stdout.strip() or commands["ip_route"].stdout.strip(),
        dns_resolvers=resolvers,
        time_sync_status=time_sync_status,
        disk_usage=commands["df_h"].stdout.strip(),
        memory_swap=commands["free_h"].stdout.strip(),
        mounted_filesystems=commands["findmnt"].stdout.strip() or commands["df_h"].stdout.strip(),
        network_interfaces=network_lines,
        interface_names=interface_names,
        wireguard_interfaces=wireguard_interfaces,
        ports=port_scan,
        detected_binaries=detected_binaries,
        detected_services=detected_services,
        detected_artifacts=detected_artifacts,
        cni_interfaces=cni_interfaces,
        firewall_backend=firewall_backend,
        commands=commands,
    )
