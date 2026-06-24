"""Shared helpers for live self-hosted runner integration scripts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT_DIR = Path("reports/styx/runner-integration")

sys.path.insert(0, str(REPO_ROOT / ".github" / "scripts"))
from runner_config import prepare_styx_yaml  # noqa: E402


def runner_name() -> str:
    return (
        os.environ.get("RUNNER_NAME")
        or os.environ.get("STYX_RUNNER_NAME")
        or Path("/etc/hostname").read_text(encoding="utf-8").strip()
    )


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
    return run(["styxctl", *args], timeout=timeout)


def pass_check(checks: list[dict[str, object]], name: str, detail: str = "ok") -> None:
    checks.append({"name": name, "status": "passed", "detail": detail})
    print(f"OK    {name}: {detail}")


def fail_check(checks: list[dict[str, object]], name: str, detail: str) -> None:
    checks.append({"name": name, "status": "failed", "detail": detail})
    print(f"FAIL  {name}: {detail}", file=sys.stderr)


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
    print(json.dumps(summary, indent=2))
    return path


def exit_from_checks(runner: str, stage: str, checks: list[dict[str, object]]) -> int:
    write_report(runner, stage, checks)
    failed = sum(1 for item in checks if item["status"] == "failed")
    if failed:
        print(f"\n{failed} check(s) failed on {runner} ({stage})", file=sys.stderr)
        return 1
    print(f"\nAll {stage} checks passed on {runner}")
    return 0
