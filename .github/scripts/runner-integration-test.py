#!/usr/bin/env python3
"""Real integration checks executed on each live self-hosted styx runner.

These tests hit the actual host: inventory, sysprep, config, plans, and (on the
hub) live UDP LAN election plus LAN reachability to the peer Pi.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT_DIR = Path("reports/styx/runner-integration")
HUB_RUNNERS = frozenset({"pegasus", "atlas"})


def _run(cmd: list[str], *, timeout: float = 120.0) -> tuple[int, str]:
    completed = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=REPO_ROOT,
    )
    output = (completed.stdout + completed.stderr).strip()
    return completed.returncode, output


def _run_styxctl(*args: str, timeout: float = 120.0) -> tuple[int, str]:
    return _run(["styxctl", *args], timeout=timeout)


def _prepare_styx_yaml() -> Path:
    target = REPO_ROOT / "styx.yaml"
    system_config = Path("/etc/styx/styx.yaml")
    if system_config.is_file():
        target.write_text(system_config.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"Using {system_config}")
        return target
    homelab = REPO_ROOT / "styx.yaml.homelab"
    if homelab.is_file():
        target.write_text(homelab.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"Using {homelab}")
        return target
    example = REPO_ROOT / "styx.yaml.example"
    target.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"Using {example}")
    return target


def _fail(checks: list[dict[str, object]], name: str, detail: str) -> None:
    checks.append({"name": name, "status": "failed", "detail": detail})
    print(f"FAIL  {name}: {detail}", file=sys.stderr)


def _pass(checks: list[dict[str, object]], name: str, detail: str = "ok") -> None:
    checks.append({"name": name, "status": "passed", "detail": detail})
    print(f"OK    {name}: {detail}")


def _skip(checks: list[dict[str, object]], name: str, detail: str) -> None:
    checks.append({"name": name, "status": "skipped", "detail": detail})
    print(f"SKIP  {name}: {detail}")


def _check_runner_identity(checks: list[dict[str, object]], runner_name: str) -> None:
    from styxctl.config import load_config
    from styxctl.inventory import collect_inventory
    from styxctl.nodes import identify_local_node, parse_nodes

    config = load_config(REPO_ROOT / "styx.yaml")
    inventory = collect_inventory()
    nodes = parse_nodes(config)
    local_node = identify_local_node(nodes, inventory, config)
    hostname = inventory.hostname

    if local_node is None:
        _fail(
            checks,
            "runner_identity",
            f"host {hostname!r} is not listed in styx.yaml nodes "
            f"(runner label {runner_name!r})",
        )
        return

    if local_node.name != runner_name:
        _fail(
            checks,
            "runner_identity",
            f"GitHub runner {runner_name!r} != styx node {local_node.name!r} "
            f"(hostname {hostname!r})",
        )
        return

    _pass(checks, "runner_identity", f"matched node {local_node.name} on {hostname}")


def _check_prerequisites(checks: list[dict[str, object]]) -> None:
    code, output = _run(["sudo", "-n", "true"])
    if code != 0:
        _fail(checks, "passwordless_sudo", output or "sudo -n failed")
    else:
        _pass(checks, "passwordless_sudo")

    for binary in ("python3", "ssh", "curl"):
        code, output = _run(["bash", "-lc", f"command -v {binary}"])
        if code != 0:
            _fail(checks, f"binary_{binary}", f"{binary} not found")
        else:
            _pass(checks, f"binary_{binary}", output.splitlines()[-1] if output else binary)


def _check_sysprep(checks: list[dict[str, object]]) -> None:
    code, output = _run_styxctl("sysprep", "check", "local", timeout=180.0)
    if code not in (0, 1):
        _fail(checks, "sysprep_check", output or f"exit {code}")
        return
    try:
        report_dir = next((REPO_ROOT / "reports/styx").iterdir())
        report = json.loads((report_dir / "sysprep-report.json").read_text(encoding="utf-8"))
        status = report.get("status")
    except (StopIteration, OSError, json.JSONDecodeError) as exc:
        _fail(checks, "sysprep_check", f"could not read sysprep report: {exc}")
        return
    if status in {"READY", "READY_WITH_WARNINGS"}:
        _pass(checks, "sysprep_check", f"status={status}")
    elif status == "BLOCKED":
        _fail(checks, "sysprep_check", f"host BLOCKED: {output[-500:]}")
    else:
        _fail(checks, "sysprep_check", f"unexpected status {status!r}")


def _check_config_validate(checks: list[dict[str, object]]) -> None:
    code, output = _run_styxctl("config", "validate")
    if code == 0:
        _pass(checks, "config_validate")
    else:
        _fail(checks, "config_validate", output or f"exit {code}")


def _check_readonly_plans(checks: list[dict[str, object]]) -> None:
    for command in (
        ["install", "plan", "local"],
        ["install", "plan", "cluster"],
        ["uninstall", "plan", "local"],
        ["uninstall", "plan", "cluster"],
    ):
        name = "_".join(command)
        code, output = _run_styxctl(*command, timeout=180.0)
        if code == 0:
            _pass(checks, name)
        else:
            _fail(checks, name, output[-800:] or f"exit {code}")


def _check_hub_lan_election(checks: list[dict[str, object]], runner_name: str) -> None:
    from styxctl.install import run_lan_election_preview

    report, exit_code = run_lan_election_preview(config_path=REPO_ROOT / "styx.yaml")
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    artifact = REPORT_DIR / f"{runner_name}-lan-election.json"
    artifact.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if exit_code != 0:
        _fail(checks, "lan_election_preview", f"exit {exit_code}")
        return

    verify = subprocess.run(
        [sys.executable, str(REPO_ROOT / ".github/scripts/verify-lan-election.py"), str(artifact)],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    if verify.returncode != 0:
        _fail(checks, "lan_election_verify", (verify.stdout + verify.stderr).strip())
        return

    election = report.get("lan_election") or {}
    peer_names = {peer.get("node_name") for peer in election.get("peers", [])}
    leader = (election.get("leader") or {}).get("node_name")
    _pass(
        checks,
        "lan_election_live",
        f"runner={runner_name} peers={sorted(peer_names)} leader={leader}",
    )


def _check_hub_lan_reachability(checks: list[dict[str, object]], runner_name: str) -> None:
    from styxctl.config import load_config
    from styxctl.nodes import parse_nodes

    nodes = {node.name: node for node in parse_nodes(load_config(REPO_ROOT / "styx.yaml"))}
    peer_name = "atlas" if runner_name == "pegasus" else "pegasus"
    peer = nodes.get(peer_name)
    if peer is None or not peer.lan_ip:
        _skip(checks, "hub_lan_ping", f"no lan_ip for peer {peer_name}")
        return

    code, output = _run(["ping", "-c", "1", "-W", "3", peer.lan_ip], timeout=15.0)
    if code == 0:
        _pass(checks, "hub_lan_ping", f"reachable {peer_name} at {peer.lan_ip}")
    else:
        _fail(checks, "hub_lan_ping", output or f"cannot ping {peer.lan_ip}")


def main() -> int:
    runner_name = (
        os.environ.get("RUNNER_NAME")
        or os.environ.get("STYX_RUNNER_NAME")
        or Path("/etc/hostname").read_text(encoding="utf-8").strip()
    )
    print(f"=== Styx runner integration: {runner_name} ===")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    _prepare_styx_yaml()

    checks: list[dict[str, object]] = []

    _check_runner_identity(checks, runner_name)
    _check_prerequisites(checks)
    _check_sysprep(checks)
    _check_config_validate(checks)
    _check_readonly_plans(checks)

    if runner_name in HUB_RUNNERS:
        _check_hub_lan_election(checks, runner_name)
        _check_hub_lan_reachability(checks, runner_name)
    else:
        _skip(checks, "lan_election_live", "not a co-located hub runner")
        _skip(checks, "hub_lan_ping", "not a co-located hub runner")

    summary: dict[str, object] = {
        "runner": runner_name,
        "checks": checks,
        "passed": sum(1 for item in checks if item["status"] == "passed"),
        "failed": sum(1 for item in checks if item["status"] == "failed"),
        "skipped": sum(1 for item in checks if item["status"] == "skipped"),
    }
    election_artifact = REPORT_DIR / f"{runner_name}-lan-election.json"
    if election_artifact.is_file():
        summary["lan_election"] = json.loads(election_artifact.read_text(encoding="utf-8")).get(
            "lan_election"
        )
    report_path = REPORT_DIR / f"{runner_name}.json"
    report_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))

    if summary["failed"]:
        print(f"\n{summary['failed']} check(s) failed on {runner_name}", file=sys.stderr)
        return 1
    print(f"\nAll integration checks passed on {runner_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
