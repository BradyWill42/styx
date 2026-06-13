"""Integration tests for the styxctl CLI."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from styxctl.cli import app

runner = CliRunner()
EXAMPLE_CONFIG = Path(__file__).resolve().parent.parent / "styx.yaml.example"


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "0.2.0"


def test_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "sysprep" in result.stdout
    assert "ports" in result.stdout
    assert "config" in result.stdout
    assert "report" in result.stdout


def test_sysprep_check_local_writes_reports(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["sysprep", "check", "local"])
    assert result.exit_code in (0, 1)
    assert "Styx Sysprep Report" in result.stdout
    assert "Reports saved" in result.stdout

    report_dirs = list((tmp_path / "reports" / "styx").iterdir())
    assert len(report_dirs) == 1

    json_path = report_dirs[0] / "sysprep-report.json"
    text_path = report_dirs[0] / "sysprep-report.txt"
    assert json_path.is_file()
    assert text_path.is_file()

    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["tool"] == "styxctl"
    assert report["report_type"] == "sysprep"
    assert report["status"] in {"READY", "READY_WITH_WARNINGS", "BLOCKED"}
    assert report["command"] == "styxctl sysprep check local"


def test_sysprep_check_local_blocked_exits_nonzero(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    from styxctl import cli as cli_module
    from tests.helpers import blocked_port_conflict, empty_port_scan, make_inventory

    blocked_inventory = make_inventory(
        ports=empty_port_scan(conflicts=[blocked_port_conflict()]),
    )

    monkeypatch.setattr(cli_module, "collect_inventory", lambda: blocked_inventory)
    result = runner.invoke(app, ["sysprep", "check", "local"])
    assert result.exit_code == 1
    assert "Status: BLOCKED" in result.stdout
    assert "sysprep safe preview local" in result.stdout


def test_ports_list_local():
    result = runner.invoke(app, ["ports", "list", "local"])
    assert result.exit_code == 0
    assert "47800" in result.stdout
    assert "WireGuard gateway" in result.stdout


def test_ports_check_local():
    result = runner.invoke(app, ["ports", "check", "local"])
    assert result.exit_code == 0
    assert "Styx Reserved Port Conflicts" in result.stdout


def test_sysprep_safe_preview_local():
    result = runner.invoke(app, ["sysprep", "safe", "preview", "local"])
    assert result.exit_code == 0
    assert "Mode: dry-run" in result.stdout
    assert "Planned actions:" in result.stdout


def test_ports_clear_preview_local():
    result = runner.invoke(app, ["ports", "clear", "preview", "local"])
    assert result.exit_code == 0
    assert "Mode: dry-run" in result.stdout


def test_config_validate_example(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "styx.yaml"
    config_path.write_text(EXAMPLE_CONFIG.read_text(encoding="utf-8"), encoding="utf-8")
    result = runner.invoke(app, ["config", "validate"])
    assert result.exit_code == 0
    assert "Config status: VALID" in result.stdout


def test_config_show_example(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "styx.yaml"
    config_path.write_text(EXAMPLE_CONFIG.read_text(encoding="utf-8"), encoding="utf-8")
    result = runner.invoke(app, ["config", "show"])
    assert result.exit_code == 0
    assert "Cluster: styx" in result.stdout
    assert "WireGuard: Styx on port 47800" in result.stdout


def test_report_show_local(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    check = runner.invoke(app, ["sysprep", "check", "local"])
    assert check.exit_code in (0, 1)

    result = runner.invoke(app, ["report", "show", "local"])
    assert result.exit_code == 0
    assert "Styx Sysprep Report" in result.stdout

    json_result = runner.invoke(app, ["report", "json", "local"])
    assert json_result.exit_code == 0
    payload = json.loads(json_result.stdout)
    assert payload["tool"] == "styxctl"


def test_report_show_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["report", "show", "local"])
    assert result.exit_code == 1
    assert "No saved sysprep report found" in result.stdout


def test_future_command_placeholder():
    result = runner.invoke(app, ["install", "soon"])
    assert result.exit_code == 0
    assert "MVP2" in result.stdout


def test_completion_scripts():
    for shell in ("bash", "zsh", "fish"):
        result = runner.invoke(app, ["completion", shell])
        assert result.exit_code == 0, result.stdout + result.stderr
        assert "styxctl" in result.stdout
