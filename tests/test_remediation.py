"""Tests for safe local remediation planning and application."""

from __future__ import annotations

from unittest.mock import patch

from styxctl.ports import PortConflict
from styxctl.remediation import (
    apply_port_clear,
    apply_safe_sysprep,
    build_port_clear_plan,
    build_safe_sysprep_plan,
)

from tests.helpers import empty_port_scan, make_inventory


def _remediation_inventory(**overrides):
    conflicts = [
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
    ]
    return make_inventory(
        network_interfaces=["wg0 UNKNOWN 10.0.0.8/24"],
        interface_names=["wg0"],
        wireguard_interfaces=["wg0"],
        ports=empty_port_scan(conflicts=conflicts),
        detected_services={
            "k3s": {"active": "active", "enabled": "enabled"},
            "k3s_agent": {"active": "inactive", "enabled": "disabled"},
        },
        detected_artifacts={
            "old_k3s_files": ["/var/lib/rancher/k3s"],
            "old_kubelet_state": [],
            "old_cni_configs": [],
            "old_flannel_state": [],
            "old_cni_interfaces": [],
            "old_flannel_interfaces": [],
            "old_styx_interface_exact": [],
            "old_temporary_styx_files": ["/tmp/styx-old.sock"],
        },
        **overrides,
    )


def test_build_port_clear_plan_includes_only_safe_conflicts():
    plan = build_port_clear_plan(_remediation_inventory())
    assert len(plan.planned) == 1
    assert plan.planned[0].target == "47800/udp"
    assert any("47801/tcp" in item for item in plan.skipped)


def test_build_safe_sysprep_plan_includes_services_and_temp_files():
    plan = build_safe_sysprep_plan(_remediation_inventory())
    targets = {item.target for item in plan.planned}
    assert "47800/udp" in targets
    assert "k3s.service" in targets
    assert "/tmp/styx-old.sock" in targets
    assert any("preserved interfaces" in item for item in plan.skipped)
    assert any("old k3s files detected" in item for item in plan.skipped)


def test_apply_port_clear_dry_run_makes_no_changes():
    result = apply_port_clear(_remediation_inventory(), dry_run=True)
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
    inventory = _remediation_inventory()
    with patch("styxctl.remediation.check_reserved_ports", return_value=inventory.ports):
        result = apply_port_clear(inventory, dry_run=False)
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
    result = apply_safe_sysprep(_remediation_inventory(), dry_run=False)
    assert mock_port_clear.called
    assert mock_systemctl.called
    assert mock_remove.called
    assert result.outcomes
