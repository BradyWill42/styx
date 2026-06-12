"""Tests for MVP2 prerequisite installation."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from styxctl.cli import app
from styxctl.inventory import SystemInventory
from styxctl.ports import PortScanResult
from styxctl.prerequisites import (
    PrerequisitePlan,
    PrerequisiteStep,
    build_prerequisite_plan,
    detect_package_manager,
    execute_prerequisite_plan,
    run_prerequisites_install,
)

runner = CliRunner()


def _empty_inventory(**overrides) -> SystemInventory:
    base = SystemInventory(
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
            conflicts=[],
        ),
        detected_binaries={
            "k3s": None,
            "wg": None,
            "ss": None,
            "curl": "/usr/bin/curl",
            "wazuh-control": None,
            "wazuh-agentd": None,
            "watchdog": None,
        },
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
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def test_detect_package_manager_on_linux():
    assert detect_package_manager() in {"apt", "dnf", "yum", "apk", None}


def test_build_prerequisite_plan_includes_missing_packages():
    inventory = _empty_inventory()
    plan = build_prerequisite_plan(inventory)

    assert plan.sysprep_status == "READY"
    package_step = next(step for step in plan.steps if step.name == "system-packages")
    assert package_step.status in {"pending", "deferred"}
    k3s_step = next(step for step in plan.steps if step.name == "k3s")
    assert k3s_step.status == "pending"


def test_build_prerequisite_plan_defers_k3s_when_artifacts_present():
    inventory = _empty_inventory(
        detected_artifacts={
            "old_k3s_files": ["/var/lib/rancher/k3s"],
            "old_kubelet_state": [],
            "old_cni_configs": [],
            "old_flannel_state": [],
            "old_cni_interfaces": [],
            "old_flannel_interfaces": [],
            "old_styx_interface_exact": [],
            "old_temporary_styx_files": [],
        }
    )
    plan = build_prerequisite_plan(inventory)
    k3s_step = next(step for step in plan.steps if step.name == "k3s")
    assert k3s_step.status == "deferred"


def test_build_prerequisite_plan_honors_siem_config():
    inventory = _empty_inventory()
    plan = build_prerequisite_plan(inventory, {"siem": {"enabled": True, "provider": "wazuh"}})
    wazuh_step = next(step for step in plan.steps if step.name == "wazuh-agent")
    assert wazuh_step.status == "deferred"


def test_execute_prerequisite_plan_dry_run_keeps_pending():
    plan = PrerequisitePlan(
        hostname="test-node",
        package_manager="apt",
        sysprep_status="READY",
        warnings=[],
        blocking=[],
        steps=[
            PrerequisiteStep(
                name="system-packages",
                category="packages",
                action="install",
                status="pending",
                reason="missing",
                command=["sudo", "apt-get", "install", "-y", "iproute2"],
            )
        ],
    )
    result = execute_prerequisite_plan(plan, dry_run=True)
    assert result.overall_status == "DRY_RUN"
    assert result.plan.steps[0].status == "pending"


def test_run_prerequisites_install_blocked_without_force():
    inventory = _empty_inventory(
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
        )
    )
    from styxctl.ports import PortConflict

    inventory.ports.conflicts = [
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
    ]
    result = run_prerequisites_install(inventory=inventory, dry_run=False, force=False)
    assert result.overall_status == "BLOCKED"


def test_install_prerequisites_local_dry_run_cli(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["install", "prerequisites", "local", "--dry-run"])
    assert result.exit_code == 0
    assert "Styx Prerequisites Install Report" in result.stdout
    assert "Reports saved" in result.stdout

    report_dirs = list((tmp_path / "reports" / "styx").iterdir())
    assert len(report_dirs) == 1
    report = json.loads((report_dirs[0] / "prerequisites-install-report.json").read_text())
    assert report["report_type"] == "prerequisites_install"
    assert report["dry_run"] is True


def test_install_prerequisites_local_help():
    result = runner.invoke(app, ["install", "prerequisites", "local", "--help"])
    assert result.exit_code == 0
    assert "--dry-run" in result.stdout
    assert "--force" in result.stdout
