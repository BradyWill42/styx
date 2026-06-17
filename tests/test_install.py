"""Tests for MVP2 local install."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from styxctl.cli import app
from styxctl.install import (
    InstallGateResult,
    build_install_plan,
    check_install_gate,
    run_install_cluster,
    run_install_local,
    run_install_plan_preview,
)
from styxctl.k3s_cluster import build_cluster_plan
from styxctl.inventory import SystemInventory
from styxctl.ports import PortScanResult

from tests.support import example_config_text

runner = CliRunner()


def _base_inventory(**overrides) -> SystemInventory:
    inventory = SystemInventory(
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
        bootstrap_ipv6="fd00:cafe::1",
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
            conflicts=[],
        ),
        detected_binaries={
            "k3s": None,
            "kubectl": None,
            "wg": None,
            "ss": "/usr/bin/ss",
            "curl": "/usr/bin/curl",
        },
        detected_services={
            "k3s": {"active": "inactive", "enabled": "disabled"},
        },
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
        firewall_backend={"preferred": "unknown", "binaries": {}, "services": {}},
    )
    for key, value in overrides.items():
        setattr(inventory, key, value)
    return inventory


def _write_example_config(tmp_path: Path) -> Path:
    config_path = tmp_path / "styx.yaml"
    config_path.write_text(example_config_text(), encoding="utf-8")
    return config_path


def test_check_install_gate_requires_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    gate = check_install_gate(inventory=_base_inventory())
    assert gate.ok is False
    assert "styx.yaml not found" in (gate.message or "")


def test_check_install_gate_blocks_on_sysprep_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_example_config(tmp_path)
    from styxctl.ports import PortConflict

    inventory = _base_inventory(
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
                    protocol="tcp",
                    port=47801,
                    process_name="blocker",
                    pid=42,
                    systemd_unit="blocker.service",
                    command_line="/usr/bin/blocker",
                    safe_to_stop=False,
                    raw="",
                )
            ],
        )
    )
    gate = check_install_gate(inventory=inventory)
    assert gate.ok is False
    assert gate.sysprep_status == "BLOCKED"
    assert "sysprep safe local" in (gate.message or "")


def test_build_install_plan_includes_k3s_and_styx_wireguard(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config_path = _write_example_config(tmp_path)
    gate = check_install_gate(inventory=_base_inventory(), config_path=config_path)
    plan = build_install_plan(gate)
    names = [step.name for step in plan.steps]
    assert "gateway-ssh" in names
    assert "gateway-firewall" in names
    assert "k3s" in names
    assert "styx-wireguard" in names
    k3s_step = next(step for step in plan.steps if step.name == "k3s")
    assert k3s_step.status == "pending"
    assert "--cluster-cidr" in (k3s_step.command_display or "")
    assert "--cluster-init" in (k3s_step.command_display or "")
    assert "--https-listen-port" in (k3s_step.command_display or "")
    assert "47811" in (k3s_step.command_display or "")
    assert plan.local_node == "pistyx"
    assert plan.cluster_plan is not None
    assert len(plan.cluster_plan.nodes) == 3


def test_build_cluster_plan_uses_node_ips(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config_path = _write_example_config(tmp_path)
    from styxctl.config import load_config

    config = load_config(config_path)
    cluster_plan = build_cluster_plan(config)
    assert cluster_plan.init_node == "pistyx"
    init_plan = cluster_plan.nodes[0]
    assert init_plan.role == "init-server"
    assert "10.0.0.1" in init_plan.node_ips
    assert "--node-ip" in init_plan.command_display
    assert "--tls-san" in init_plan.command_display
    assert "--https-listen-port" in init_plan.command_display


def test_install_cluster_dry_run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_example_config(tmp_path)
    monkeypatch.setattr("styxctl.install.collect_inventory", _base_inventory)
    result = runner.invoke(app, ["install", "plan", "cluster"])
    assert result.exit_code == 0
    assert "Cluster plan" in result.stdout or "cluster" in result.stdout.lower()


def test_run_install_cluster_mocked_ssh(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config_path = _write_example_config(tmp_path)
    monkeypatch.setattr("styxctl.install.collect_inventory", _base_inventory)

    def fake_ssh(target: str, command: str, **kwargs) -> tuple[bool, str]:
        if "node-token" in command:
            return True, "test-token"
        if "kubectl get nodes" in command:
            return True, '{"items":[{"metadata":{"name":"pistyx"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}'
        return True, "active"

    monkeypatch.setattr("styxctl.install._run_ssh_command", fake_ssh)
    monkeypatch.setattr(
        "styxctl.install._run_pipeline",
        lambda *args, **kwargs: (True, "local k3s installed"),
    )
    monkeypatch.setattr(
        "styxctl.k3s_cluster.refresh_node_duckdns",
        lambda config, node: (False, "mocked"),
    )
    monkeypatch.setattr(
        "styxctl.k3s_cluster._run_ssh_command",
        fake_ssh,
    )
    report, exit_code = run_install_cluster(
        dry_run=False,
        yes=True,
        config_path=config_path,
        runner=fake_ssh,
    )
    assert report["cluster"] is not None
    assert exit_code in (0, 1)


def test_run_install_local_dry_run_writes_report(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_example_config(tmp_path)
    monkeypatch.setattr("styxctl.install.collect_inventory", _base_inventory)

    result = runner.invoke(app, ["install", "plan", "local"])
    assert result.exit_code == 0
    assert "Styx Install Report" in result.stdout
    assert "Reports saved" in result.stdout

    report_dir = tmp_path / "reports" / "styx" / "test-node"
    report = json.loads((report_dir / "install-report.json").read_text(encoding="utf-8"))
    assert report["report_type"] == "install"
    assert report["dry_run"] is True


def test_install_plan_local_blocked_without_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("styxctl.install.collect_inventory", _base_inventory)
    result = runner.invoke(app, ["install", "plan", "local"])
    assert result.exit_code == 1
    assert "Install blocked" in result.stdout


def test_install_status_local_reports_issues(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_example_config(tmp_path)
    monkeypatch.setattr("styxctl.install.collect_inventory", _base_inventory)
    result = runner.invoke(app, ["install", "status", "local"])
    assert result.exit_code == 1
    assert "k3s installed" in result.stdout
    assert "Issues:" in result.stdout


def test_install_doctor_local_exit_code(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_example_config(tmp_path)
    monkeypatch.setattr("styxctl.install.collect_inventory", _base_inventory)
    result = runner.invoke(app, ["install", "doctor", "local"])
    assert result.exit_code == 1
    assert "blocking issues found" in result.stdout


def test_run_install_local_blocked_returns_exit_one(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_example_config(tmp_path)
    monkeypatch.setattr("styxctl.install.collect_inventory", _base_inventory)
    gate = InstallGateResult(
        ok=False,
        message="blocked",
        config={},
        config_path=tmp_path / "styx.yaml",
        config_status_value="VALID",
        inventory=_base_inventory(),
        sysprep_status="BLOCKED",
        warnings=[],
        blocking=["blocked"],
    )
    monkeypatch.setattr("styxctl.install.check_install_gate", lambda **kwargs: gate)
    report, exit_code = run_install_local(dry_run=True, yes=False, config_path=tmp_path / "styx.yaml")
    assert exit_code == 1
    assert report["status"] == "FAILED"


def test_run_install_plan_preview(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_example_config(tmp_path)
    monkeypatch.setattr("styxctl.install.collect_inventory", _base_inventory)
    report, exit_code = run_install_plan_preview(config_path=tmp_path / "styx.yaml")
    assert exit_code == 0
    assert report["command"] == "styxctl install plan local"
