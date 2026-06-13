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

PORT_PLAN: dict[int, dict[str, str]] = {
    47800: {"protocol": "udp", "purpose": "Styx production WireGuard gateway"},
    47801: {"protocol": "tcp", "purpose": "Styx gateway health API"},
    47802: {"protocol": "tcp", "purpose": "Styx director API"},
    47803: {"protocol": "tcp", "purpose": "Styx status dashboard/API"},
    47804: {"protocol": "tcp", "purpose": "Styx node agent API"},
    47805: {"protocol": "tcp", "purpose": "Styx Ansible controller API"},
    47806: {"protocol": "tcp", "purpose": "Styx watchdog agent API"},
    47807: {"protocol": "tcp", "purpose": "Styx local diagnostics API"},
    47808: {"protocol": "tcp", "purpose": "Styx metrics exporter"},
    47809: {"protocol": "any", "purpose": "reserved"},
}

PORT_BLOCKS: tuple[tuple[str, int, int], ...] = (
    ("site/gateway testing", 47810, 47819),
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
    """Return the configured Styx purpose for a reserved port."""
    if port in PORT_PLAN:
        return PORT_PLAN[port]["purpose"]
    for purpose, start, end in PORT_BLOCKS:
        if start <= port <= end:
            return purpose
    return "outside Styx reserved range"


def planned_protocol(port: int) -> str:
    if port in PORT_PLAN:
        return PORT_PLAN[port]["protocol"]
    return "any"


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


def _scan_result(*, scanner: str, command_available: bool, **fields: object) -> PortScanResult:
    return PortScanResult(
        range_start=RESERVED_PORT_START,
        range_end=RESERVED_PORT_END,
        scanner=scanner,
        command_available=command_available,
        returncode=fields.get("returncode"),
        timed_out=bool(fields.get("timed_out")),
        error=fields.get("error"),
        stdout=str(fields.get("stdout") or ""),
        stderr=str(fields.get("stderr") or ""),
        conflicts=fields.get("conflicts") or [],
    )


def check_reserved_ports(timeout: float = 5.0) -> PortScanResult:
    """Check only the Styx reserved range, 47800-47850."""
    scanner = shutil.which("ss")
    if scanner is None:
        return _scan_result(
            scanner="ss -H -lntup",
            command_available=False,
            error="ss command not found; install iproute2 to enable port scanning.",
        )

    command = [scanner, "-H", "-lntup"]
    scanner_label = " ".join(command)
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return _scan_result(
            scanner=scanner_label,
            command_available=True,
            timed_out=True,
            error=f"ss timed out after {timeout} seconds",
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
        )

    stdout = completed.stdout or ""
    return _scan_result(
        scanner=scanner_label,
        command_available=True,
        returncode=completed.returncode,
        error=None if completed.returncode == 0 else "ss returned a nonzero exit code",
        stdout=stdout,
        stderr=completed.stderr or "",
        conflicts=parse_ss_output(stdout),
    )


def conflicts_for_port(conflicts: Iterable[PortConflict], port: int) -> list[PortConflict]:
    return [conflict for conflict in conflicts if conflict.port == port]
