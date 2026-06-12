"""Tests for safe local remediation planning and application."""

from __future__ import annotations

from unittest.mock import patch

from styxctl.inventory import SystemInventory
from styxctl.ports import PortConflict, PortScanResult
from styxctl.remediation import (
    apply_port_clear,
    apply_safe_sysprep,
    build_port_clear_plan,
    build_safe_sysprep_plan,
)


def _inventory(**overrides) -> SystemInventory:
    defaults = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "hostname": "test-node",
        "fqdn": "test-node.local",
        "os_version": "Test OS",
        "architecture": "x86_64",
        "kernel_version": "6.1.0",
        "boot_time": None,
        "current_user": "tester",
        "sudo_available": True,
        "primary_lan_ip": "10.0.0.1",
        "bootstrap_ipv4": "10.0.0.1",
        "bootstrap_ipv6": None,
        "default_route": "default via 10.0.0.254",
        "dns_resolvers": ["10.0.0.2"],
        "time_sync_status": "System clock synchronized: yes",
        "disk_usage": "",
        "memory_swap": "",
        "mounted_filesystems": "",
        "network_interfaces": ["wg0 UNKNOWN 10.0.0.8/24"],
        "interface_names": ["wg0"],
        "wireguard_interfaces": ["wg0"],
        "ports": PortScanResult(
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
                ),
                PortConflict(
                    protocol="tcp",
                    port=47801,
                    process_name="caddy",
                    pid=999,
                    systemd_unit="caddy.service",
                    command_line="/usr/bin/caddy",
                    safe_to_stop=False,
                    raw="",
                ),
            ],
        ),
        "detected_binaries": {},
        "detected_services": {
            "k3s": {"active": "active", "enabled": "enabled"},
            "k3s_agent": {"active": "inactive", "enabled": "disabled"},
        },
        "detected_artifacts": {
            "old_k3s_files": ["/var/lib/rancher/k3s"],
            "old_kubelet_state": [],
            "old_cni_configs": [],
            "old_flannel_state": [],
            "old_cni_interfaces": [],
            "old_flannel_interfaces": [],
            "old_styx_interface_exact": [],
            "old_temporary_styx_files": ["/tmp/styx-old.sock"],
        },
        "cni_interfaces": [],
        "firewall_backend": {"preferred": "unknown"},
    }
    defaults.update(overrides)
    return SystemInventory(**defaults)


def test_build_port_clear_plan_includes_only_safe_conflicts():
    plan = build_port_clear_plan(_inventory())
    assert len(plan.planned) == 1
    assert plan.planned[0].target == "47800/udp"
    assert any("47801/tcp" in item for item in plan.skipped)


def test_build_safe_sysprep_plan_includes_services_and_temp_files():
    plan = build_safe_sysprep_plan(_inventory())
    targets = {item.target for item in plan.planned}
    assert "47800/udp" in targets
    assert "k3s.service" in targets
    assert "/tmp/styx-old.sock" in targets
    assert any("preserved interfaces" in item for item in plan.skipped)
    assert any("old k3s files detected" in item for item in plan.skipped)


def test_apply_port_clear_dry_run_makes_no_changes():
    result = apply_port_clear(_inventory(), dry_run=True)
    assert result.dry_run is True
    assert result.outcomes == []


@patch("styxctl.remediation._stop_pid")
def test_apply_port_clear_applies_safe_actions(mock_stop):
    mock_stop.return_value = type("Outcome", (), {
        "category": "port",
        "target": "47800/udp",
        "action": "stop",
        "status": "applied",
        "detail": "ok",
    })()
    with patch("styxctl.remediation.check_reserved_ports", return_value=_inventory().ports):
        result = apply_port_clear(_inventory(), dry_run=False)
    assert mock_stop.called
    assert result.outcomes


@patch("styxctl.remediation._remove_path")
@patch("styxctl.remediation.apply_port_clear")
@patch("styxctl.remediation._systemctl_action")
def test_apply_safe_sysprep_applies_service_and_file_actions(mock_systemctl, mock_port_clear, mock_remove):
    mock_port_clear.return_value = type("Result", (), {"outcomes": [], "skipped": []})()
    mock_systemctl.return_value = type("Outcome", (), {
        "category": "service",
        "target": "k3s.service",
        "action": "stop",
        "status": "applied",
        "detail": "ok",
    })()
    mock_remove.return_value = type("Outcome", (), {
        "category": "file",
        "target": "/tmp/styx-old.sock",
        "action": "remove",
        "status": "applied",
        "detail": "ok",
    })()
    result = apply_safe_sysprep(_inventory(), dry_run=False)
    assert mock_port_clear.called
    assert mock_systemctl.called
    assert mock_remove.called
    assert result.outcomes
