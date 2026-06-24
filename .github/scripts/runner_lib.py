"""Shared helpers for live self-hosted runner integration scripts."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT_DIR = Path("reports/styx/runner-integration")
BOOTSTRAP_SSH_PORT = 22


def runner_name() -> str:
    return (
        os.environ.get("RUNNER_NAME")
        or os.environ.get("STYX_RUNNER_NAME")
        or Path("/etc/hostname").read_text(encoding="utf-8").strip()
    )


def prepare_styx_yaml(repo_root: Path | None = None) -> Path:
    """Copy styx.yaml.example into styx.yaml for runner integration."""
    root = repo_root or REPO_ROOT
    target = root / "styx.yaml"
    example = root / "styx.yaml.example"
    if not example.is_file():
        raise FileNotFoundError(f"Missing config example: {example}")
    target.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"Using {example}")
    return target


def styxctl_command() -> list[str]:
    binary = shutil.which("styxctl")
    if binary:
        return [binary]
    return [sys.executable, "-m", "styxctl.cli"]


def run(cmd: list[str], *, timeout: float = 120.0) -> tuple[int, str]:
    completed = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=REPO_ROOT,
    )
    return completed.returncode, (completed.stdout + completed.stderr).strip()


def run_styxctl(*args: str, timeout: float = 120.0) -> tuple[int, str]:
    return run([*styxctl_command(), *args], timeout=timeout)


def pass_check(checks: list[dict[str, object]], name: str, detail: str = "ok") -> None:
    checks.append({"name": name, "status": "passed", "detail": detail})
    print(f"OK    {name}: {detail}")


def fail_check(checks: list[dict[str, object]], name: str, detail: str) -> None:
    checks.append({"name": name, "status": "failed", "detail": detail})
    print(f"FAIL  {name}: {detail}", file=sys.stderr)


def port_listening(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=2.0):
            return True
    except OSError:
        return False


def run_ssh_probe(
    target: str,
    remote_command: str,
    *,
    port: int,
    jump: str | None = None,
    timeout: float = 30.0,
) -> tuple[bool, str]:
    """SSH for runner integration tests (accept-new host keys on first peer contact)."""
    if shutil.which("ssh") is None:
        return False, "ssh command not found"
    command = [
        "ssh",
        "-p",
        str(port),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "StrictHostKeyChecking=accept-new",
    ]
    if jump:
        command.extend(["-J", f"{jump}:{port}"])
    command.extend([target, remote_command])
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=REPO_ROOT,
        )
    except subprocess.TimeoutExpired:
        return False, f"ssh timed out after {timeout} seconds"
    except OSError as exc:
        return False, str(exc)
    detail = (completed.stderr or completed.stdout or "").strip()
    if completed.returncode == 0:
        return True, detail or "ok"
    return False, detail or f"ssh exit code {completed.returncode}"


def configure_styx_gateway(config_path: Path) -> tuple[bool, str]:
    """Ensure Styx gateway SSH and firewall are configured for connectivity tests."""
    from styxctl.bootstrap_config import load_operational_config
    from styxctl.gateway import parse_gateway_ports
    from styxctl.install import _apply_gateway_firewall, _configure_gateway_ssh
    from styxctl.inventory import collect_inventory

    inventory = collect_inventory()
    config = load_operational_config(config_path, inventory=inventory)
    gateway = parse_gateway_ports(config)
    wireguard = config.get("wireguard")
    wg_port = 47800
    if isinstance(wireguard, dict) and isinstance(wireguard.get("port"), int):
        wg_port = wireguard["port"]

    ok, detail = _configure_gateway_ssh(gateway.ssh, inventory)
    if not ok:
        return False, f"gateway-ssh: {detail}"

    ok, detail = _apply_gateway_firewall(wg_port, gateway.ssh, gateway.k3s_api, inventory)
    if not ok:
        return False, f"gateway-firewall: {detail}"

    if not port_listening(gateway.ssh):
        return False, f"gateway port {gateway.ssh} is not listening locally after configure"
    return True, f"gateway ssh listening on {gateway.ssh}"


def write_report(runner: str, stage: str, checks: list[dict[str, object]]) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    summary: dict[str, object] = {
        "runner": runner,
        "stage": stage,
        "checks": checks,
        "passed": sum(1 for item in checks if item["status"] == "passed"),
        "failed": sum(1 for item in checks if item["status"] == "failed"),
    }
    path = REPORT_DIR / f"{runner}-{stage}.json"
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return path


def format_report(path: Path) -> str:
    """Human-readable summary of a stage JSON report."""
    data = json.loads(path.read_text(encoding="utf-8"))
    lines = [
        f"=== {data.get('runner')} / {data.get('stage')} ===",
        f"passed: {data.get('passed', 0)}  failed: {data.get('failed', 0)}",
        "",
    ]
    for check in data.get("checks", []):
        status = str(check.get("status", "?")).upper()
        name = check.get("name", "?")
        detail = str(check.get("detail", "")).strip()
        prefix = "OK  " if status == "PASSED" else "FAIL"
        if detail and detail != "ok":
            lines.append(f"{prefix}  {name}: {detail}")
        else:
            lines.append(f"{prefix}  {name}")
    return "\n".join(lines).rstrip() + "\n"


def print_report(runner: str, stage: str) -> int:
    path = REPORT_DIR / f"{runner}-{stage}.json"
    if not path.is_file():
        print(f"Report not found: {path}", file=sys.stderr)
        return 1
    print(format_report(path), end="")
    data = json.loads(path.read_text(encoding="utf-8"))
    return 1 if int(data.get("failed", 0)) > 0 else 0


def exit_from_checks(runner: str, stage: str, checks: list[dict[str, object]]) -> int:
    path = write_report(runner, stage, checks)
    print(format_report(path), end="")
    failed = sum(1 for item in checks if item["status"] == "failed")
    if failed:
        print(f"{failed} check(s) failed on {runner} ({stage})", file=sys.stderr)
        return 1
    print(f"All {stage} checks passed on {runner}")
    return 0
