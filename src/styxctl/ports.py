"""Reserved Styx port range helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re
import shutil
import subprocess
from typing import Iterable


RESERVED_PORT_START = 47800
RESERVED_PORT_END = 47850
RESERVED_PORT_RANGE = range(RESERVED_PORT_START, RESERVED_PORT_END + 1)
ADMIN_SSH_PORT = 22

# Each reserved port maps to a LIST of {protocol, purpose} entries: one port number can carry two
# services when they use different transports, because the kernel binds each (protocol, port) tuple
# separately. Styx uses this on 47800 (WireGuard/udp + gateway SSH/tcp) and 47801 (pistyx client
# egress/udp + k3s API/tcp). Port 22 stays admin/runner SSH.
PORT_PLAN: dict[int, list[dict[str, str]]] = {
    47800: [
        {"protocol": "udp", "purpose": "Styx backbone WireGuard mesh"},
        {"protocol": "tcp", "purpose": "Styx gateway SSH"},
    ],
    47801: [
        {"protocol": "udp", "purpose": "pistyx client WireGuard egress (StyxEgress)"},
        {"protocol": "tcp", "purpose": "k3s API gateway listen"},
    ],
    47802: [{"protocol": "udp", "purpose": "Styx director API / LAN leader election"}],
    47803: [{"protocol": "tcp", "purpose": "Styx status dashboard/API"}],
    47804: [{"protocol": "tcp", "purpose": "Styx node agent API"}],
    47805: [{"protocol": "tcp", "purpose": "Styx Ansible controller API"}],
    47806: [{"protocol": "tcp", "purpose": "Styx watchdog agent API"}],
    47807: [{"protocol": "tcp", "purpose": "Styx local diagnostics API"}],
    47808: [{"protocol": "tcp", "purpose": "Styx metrics exporter"}],
    47809: [{"protocol": "any", "purpose": "reserved"}],
    47810: [{"protocol": "tcp", "purpose": "Styx gateway health API (reserved)"}],
    47811: [{"protocol": "any", "purpose": "reserved (freed; formerly k3s API)"}],
}

PORT_BLOCKS: tuple[tuple[str, int, int], ...] = (
    ("site/gateway spare", 47812, 47819),
    ("client/profile testing", 47820, 47829),
    ("development/debug", 47830, 47839),
    ("reserved future", 47840, 47850),
)


@dataclass(slots=True)
class PortConflict:
    protocol: str
    port: int
    process_name: str | None
    pid: int | None
    systemd_unit: str | None
    command_line: str | None
    safe_to_stop: bool
    raw: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class PortScanResult:
    range_start: int
    range_end: int
    scanner: str
    command_available: bool
    returncode: int | None
    timed_out: bool
    error: str | None
    stdout: str
    stderr: str
    conflicts: list[PortConflict]

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["conflicts"] = [conflict.to_dict() for conflict in self.conflicts]
        return data


def port_purpose(port: int) -> str:
    """Return the Styx purpose(s) for a reserved port; co-located protocols are joined with ' + '."""
    if port in PORT_PLAN:
        return " + ".join(entry["purpose"] for entry in PORT_PLAN[port])
    for purpose, start, end in PORT_BLOCKS:
        if start <= port <= end:
            return purpose
    return "outside Styx reserved range"


def port_purpose_for(port: int, protocol: str) -> str:
    """Return the purpose for one (port, protocol); falls back to the aggregate purpose."""
    if port in PORT_PLAN:
        for entry in PORT_PLAN[port]:
            if entry["protocol"] in (protocol, "any"):
                return entry["purpose"]
    return port_purpose(port)


def planned_protocols(port: int) -> list[str]:
    """Every protocol Styx plans to bind on a reserved port (e.g. ['udp', 'tcp'] on 47800)."""
    if port in PORT_PLAN:
        return [entry["protocol"] for entry in PORT_PLAN[port]]
    return ["any"]


def planned_protocol(port: int) -> str:
    """Compact protocol label for a reserved port ('udp+tcp' when two transports share it)."""
    if port in PORT_PLAN:
        return "+".join(dict.fromkeys(planned_protocols(port)))
    return "any"


def styx_planned_listeners() -> set[tuple[int, str]]:
    """The (port, protocol) pairs Styx itself binds inside the reserved range.

    Used to tell Styx's own expected listeners apart from foreign squatters when a scan finds a
    reserved port occupied — e.g. on a re-install the gateway SSH is already on 47800/tcp.
    """
    pairs: set[tuple[int, str]] = set()
    for port, entries in PORT_PLAN.items():
        for entry in entries:
            pairs.add((port, entry["protocol"]))
    return pairs


def extract_port(address: str) -> int | None:
    """Extract the numeric port from common ss local-address formats."""
    address = address.strip()
    if not address or address in {"*", "*:*"}:
        return None

    # Examples handled: 0.0.0.0:47800, *:47801, [::]:47802,
    # [fe80::1%eth0]:47803, :::47804.
    match = re.search(r":(\d+)$", address)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def parse_process(line: str) -> tuple[str | None, int | None]:
    """Parse process name and PID from ss output when visible."""
    match = re.search(r'users:\(\("(?P<name>[^"]+)",pid=(?P<pid>\d+)', line)
    if not match:
        return None, None
    return match.group("name"), int(match.group("pid"))


def proc_cmdline(pid: int | None) -> str | None:
    if pid is None:
        return None
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return None
    cleaned = raw.replace(b"\x00", b" ").decode(errors="replace").strip()
    return cleaned or None


def proc_systemd_unit(pid: int | None) -> str | None:
    if pid is None:
        return None
    try:
        cgroup = Path(f"/proc/{pid}/cgroup").read_text(errors="replace")
    except OSError:
        return None

    patterns = (
        r"/system\.slice/(?P<unit>[^/\s]+\.(?:service|scope))",
        r"/user\.slice/.+?/(?P<unit>[^/\s]+\.(?:service|scope))",
    )
    for pattern in patterns:
        match = re.search(pattern, cgroup)
        if match:
            return match.group("unit")
    return None


def infer_safe_to_stop(process_name: str | None, systemd_unit: str | None, command_line: str | None) -> bool:
    """Best-effort safety label for MVP1 remediation.

    MVP1 only acts on conflicts marked safe to stop.
    """
    haystack = " ".join(part for part in (process_name, systemd_unit, command_line) if part).lower()
    if not haystack:
        return False

    known_styx_or_k3s_tokens = (
        "styx",
        "old-styx",
        "k3s",
        "flannel",
        "cni",
    )
    return any(token in haystack for token in known_styx_or_k3s_tokens)


def _line_to_conflict(line: str) -> PortConflict | None:
    fields = line.split()
    if not fields:
        return None

    protocol = fields[0].lower()
    if protocol.startswith("tcp"):
        protocol = "tcp"
    elif protocol.startswith("udp"):
        protocol = "udp"
    else:
        return None

    port = None
    for field in fields:
        candidate = extract_port(field)
        if candidate in RESERVED_PORT_RANGE:
            port = candidate
            break
    if port is None:
        return None

    process_name, pid = parse_process(line)
    command_line = proc_cmdline(pid)
    systemd_unit = proc_systemd_unit(pid)
    safe_to_stop = infer_safe_to_stop(process_name, systemd_unit, command_line)
    return PortConflict(
        protocol=protocol,
        port=port,
        process_name=process_name,
        pid=pid,
        systemd_unit=systemd_unit,
        command_line=command_line,
        safe_to_stop=safe_to_stop,
        raw=line,
    )


def parse_ss_output(output: str) -> list[PortConflict]:
    conflicts: list[PortConflict] = []
    for line in output.splitlines():
        conflict = _line_to_conflict(line)
        if conflict is not None:
            conflicts.append(conflict)
    return sorted(conflicts, key=lambda item: (item.port, item.protocol, item.pid or 0))


def check_reserved_ports(timeout: float = 5.0) -> PortScanResult:
    """Check only the Styx reserved range, 47800-47850."""
    scanner = shutil.which("ss")
    if scanner is None:
        return PortScanResult(
            range_start=RESERVED_PORT_START,
            range_end=RESERVED_PORT_END,
            scanner="ss -H -lntup",
            command_available=False,
            returncode=None,
            timed_out=False,
            error="ss command not found; install iproute2 to enable port scanning.",
            stdout="",
            stderr="",
            conflicts=[],
        )

    command = [scanner, "-H", "-lntup"]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return PortScanResult(
            range_start=RESERVED_PORT_START,
            range_end=RESERVED_PORT_END,
            scanner=" ".join(command),
            command_available=True,
            returncode=None,
            timed_out=True,
            error=f"ss timed out after {timeout} seconds",
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            conflicts=[],
        )

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    conflicts = parse_ss_output(stdout)
    return PortScanResult(
        range_start=RESERVED_PORT_START,
        range_end=RESERVED_PORT_END,
        scanner=" ".join(command),
        command_available=True,
        returncode=completed.returncode,
        timed_out=False,
        error=None if completed.returncode == 0 else "ss returned a nonzero exit code",
        stdout=stdout,
        stderr=stderr,
        conflicts=conflicts,
    )


def conflicts_for_port(conflicts: Iterable[PortConflict], port: int) -> list[PortConflict]:
    return [conflict for conflict in conflicts if conflict.port == port]
