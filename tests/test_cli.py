"""Integration tests for the styxctl CLI."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from styxctl.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "0.1.0"


def test_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "sysprep" in result.stdout
    assert "ports" in result.stdout


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
    from styxctl.inventory import SystemInventory
    from styxctl.ports import PortConflict, PortScanResult

    blocked_inventory = SystemInventory(
        generated_at="2026-01-01T00:00:00+00:00",
        hostname="test-node",
        fqdn="test-node.local",
        os_version="Test OS",
        architecture="x86_64",
        kernel_version="6.1.0",
        boot_time=None,
        current_user="tester",
        sudo_available=True,
        primary_lan_ip="10.0.0.1",
        bootstrap_ipv4="10.0.0.1",
        bootstrap_ipv6=None,
        default_route="default via 10.0.0.254",
        dns_resolvers=["10.0.0.2"],
        time_sync_status="System clock synchronized: yes",
        disk_usage="",
        memory_swap="",
        mounted_filesystems="",
        network_interfaces=[],
        interface_names=[],
        wireguard_interfaces=[],
        ports=PortScanResult(
            range_start=47800,
            range_end=47850,
            scanner="ss -H -lntup",
            command_available=True,
            returncode=0,
            timed_out=False,
            error=None,
            stdout="",
            stderr="",
            conflicts=[
                PortConflict(
                    protocol="udp",
                    port=47800,
                    process_name="old-styx",
                    pid=123,
                    systemd_unit="old-styx.service",
                    command_line="/usr/bin/old-styx",
                    safe_to_stop=True,
                    raw="",
                )
            ],
        ),
        detected_binaries={},
        detected_services={},
        detected_artifacts={key: [] for key in (
            "old_k3s_files",
            "old_kubelet_state",
            "old_cni_configs",
            "old_flannel_state",
            "old_cni_interfaces",
            "old_flannel_interfaces",
            "old_styx_interface_exact",
            "old_temporary_styx_files",
        )},
        cni_interfaces=[],
        firewall_backend={"preferred": "unknown"},
    )

    monkeypatch.setattr(cli_module, "collect_inventory", lambda: blocked_inventory)
    result = runner.invoke(app, ["sysprep", "check", "local"])
    assert result.exit_code == 1
    assert "Status: BLOCKED" in result.stdout


def test_ports_list_local():
    result = runner.invoke(app, ["ports", "list", "local"])
    assert result.exit_code == 0
    assert "47800" in result.stdout
    assert "WireGuard gateway" in result.stdout


def test_ports_check_local():
    result = runner.invoke(app, ["ports", "check", "local"])
    assert result.exit_code == 0
    assert "Styx Reserved Port Conflicts" in result.stdout


def test_sysprep_safe_local_is_read_only():
    result = runner.invoke(app, ["sysprep", "safe", "local"])
    assert result.exit_code == 0
    assert "not implemented in MVP1" in result.stdout
    assert "No changes were made" in result.stdout


def test_future_command_placeholder():
    result = runner.invoke(app, ["install", "soon"])
    assert result.exit_code == 0
    assert "not implemented yet" in result.stdout


def test_completion_scripts():
    for shell in ("bash", "zsh", "fish"):
        result = runner.invoke(app, ["completion", shell])
        assert result.exit_code == 0, result.stdout + result.stderr
        assert "styxctl" in result.stdout
