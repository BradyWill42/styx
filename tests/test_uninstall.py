"""Tests for the Styx uninstall operation."""

from __future__ import annotations

from typer.testing import CliRunner

from styxctl.cli import app
from styxctl.uninstall import (
    UninstallPlan,
    UninstallStep,
    apply_uninstall_plan,
    build_uninstall_plan,
    render_uninstall_text,
    run_uninstall_local,
)

from tests.support import make_inventory

runner = CliRunner()


def _base_inventory(**overrides):
    return make_inventory(**overrides)


def test_build_uninstall_plan_all_skipped_when_nothing_installed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("styxctl.uninstall._detect_k3s_uninstall_script", lambda: None)
    inventory = _base_inventory()
    plan = build_uninstall_plan(inventory=inventory)

    assert plan.hostname == "test-node"
    assert plan.interface == "Styx"
    step_names = {step.name: step.status for step in plan.steps}
    assert step_names["wg-down"] == "skipped"
    assert step_names["remove-wg-config"] == "skipped"
    assert step_names["remove-gateway-ssh"] == "skipped"
    assert step_names["k3s-uninstall"] == "skipped"


def test_build_uninstall_plan_wg_down_pending_when_interface_up(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    inventory = _base_inventory(interface_names=["Styx"])
    plan = build_uninstall_plan(inventory=inventory)

    wg_step = next(s for s in plan.steps if s.name == "wg-down")
    assert wg_step.status == "pending"
    assert "Styx" in (wg_step.command_display or "")


def test_build_uninstall_plan_wg_down_pending_from_wireguard_interfaces(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    inventory = _base_inventory(wireguard_interfaces=["Styx"])
    plan = build_uninstall_plan(inventory=inventory)

    wg_step = next(s for s in plan.steps if s.name == "wg-down")
    assert wg_step.status == "pending"


def test_build_uninstall_plan_remove_wg_config_pending_when_file_exists(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    styx_conf = tmp_path / "Styx.conf"
    styx_conf.write_text("[Interface]\n", encoding="utf-8")
    inventory = _base_inventory()
    monkeypatch.setattr("styxctl.uninstall.STYX_WG_DIR", tmp_path)
    plan = build_uninstall_plan(inventory=inventory)

    step = next(s for s in plan.steps if s.name == "remove-wg-config")
    assert step.status == "pending"


def test_build_uninstall_plan_remove_sshd_dropin_pending_when_file_exists(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    dropin = tmp_path / "styx-gateway.conf"
    dropin.write_text("Port 47810\n", encoding="utf-8")
    monkeypatch.setattr("styxctl.uninstall.STYX_SSHD_DROPIN", dropin)
    inventory = _base_inventory()
    plan = build_uninstall_plan(inventory=inventory)

    step = next(s for s in plan.steps if s.name == "remove-gateway-ssh")
    assert step.status == "pending"


def test_build_uninstall_plan_k3s_deferred_when_binary_but_no_script(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("styxctl.uninstall._detect_k3s_uninstall_script", lambda: None)
    inventory = _base_inventory(detected_binaries={"k3s": "/usr/local/bin/k3s"})
    plan = build_uninstall_plan(inventory=inventory)

    step = next(s for s in plan.steps if s.name == "k3s-uninstall")
    assert step.status == "deferred"


def test_build_uninstall_plan_k3s_pending_when_script_found(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    script = tmp_path / "k3s-uninstall.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    script.chmod(0o755)

    monkeypatch.setattr(
        "styxctl.uninstall.K3S_UNINSTALL_SCRIPTS",
        (str(script),),
    )
    inventory = _base_inventory()
    plan = build_uninstall_plan(inventory=inventory)

    step = next(s for s in plan.steps if s.name == "k3s-uninstall")
    assert step.status == "pending"
    assert str(script) in (step.command_display or "")


def test_apply_uninstall_plan_skipped_steps_unchanged():
    plan = UninstallPlan(
        hostname="test-node",
        interface="Styx",
        steps=[
            UninstallStep(
                name="wg-down",
                category="wireguard",
                action="down",
                status="skipped",
                reason="not up",
            )
        ],
    )
    inventory = _base_inventory()
    applied = apply_uninstall_plan(plan, inventory=inventory)
    assert applied.steps[0].status == "skipped"


def test_apply_uninstall_plan_calls_mutating_for_wg_down(monkeypatch):
    calls: list[tuple] = []

    def fake_mutating(command, *, use_sudo, sudo_available, timeout=30.0):
        calls.append(tuple(command))
        return True, "ok"

    monkeypatch.setattr("styxctl.uninstall._run_mutating", fake_mutating)

    plan = UninstallPlan(
        hostname="test-node",
        interface="Styx",
        steps=[
            UninstallStep(
                name="wg-down",
                category="wireguard",
                action="down",
                status="pending",
                reason="up",
            )
        ],
    )
    applied = apply_uninstall_plan(plan, inventory=_base_inventory())
    assert applied.steps[0].status == "removed"
    assert any("wg-quick" in c and "Styx" in c for c in calls)


def test_apply_uninstall_plan_step_fails_on_mutating_error(monkeypatch):
    monkeypatch.setattr(
        "styxctl.uninstall._run_mutating",
        lambda *a, **kw: (False, "permission denied"),
    )
    plan = UninstallPlan(
        hostname="test-node",
        interface="Styx",
        steps=[
            UninstallStep(
                name="remove-wg-config",
                category="wireguard",
                action="remove",
                status="pending",
                reason="exists",
            )
        ],
    )
    applied = apply_uninstall_plan(plan, inventory=_base_inventory())
    assert applied.steps[0].status == "failed"
    assert "permission denied" in (applied.steps[0].detail or "")


def test_render_uninstall_text_dry_run():
    plan = UninstallPlan(
        hostname="myhost",
        interface="Styx",
        steps=[
            UninstallStep(
                name="wg-down",
                category="wireguard",
                action="down",
                status="pending",
                reason="interface is up",
                command_display="sudo wg-quick down Styx",
            )
        ],
    )
    text = render_uninstall_text(plan, dry_run=True)
    assert "dry-run" in text
    assert "wg-down" in text
    assert "pending" in text
    assert "sudo wg-quick down Styx" in text


def test_render_uninstall_text_apply_mode():
    plan = UninstallPlan(
        hostname="myhost",
        interface="Styx",
        steps=[
            UninstallStep(
                name="k3s-uninstall",
                category="platform",
                action="uninstall",
                status="removed",
                detail="exit 0",
            )
        ],
    )
    text = render_uninstall_text(plan, dry_run=False)
    assert "apply" in text
    assert "removed" in text


def test_run_uninstall_local_dry_run_returns_no_change(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("styxctl.uninstall.collect_inventory", _base_inventory)
    report, code = run_uninstall_local(dry_run=True)
    assert code == 0
    assert report["status"] == "DRY_RUN"
    assert report["dry_run"] is True


def test_run_uninstall_local_nothing_to_do(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("styxctl.uninstall.collect_inventory", _base_inventory)
    report, code = run_uninstall_local(dry_run=False, yes=True)
    assert code == 0
    assert report["status"] == "UNINSTALLED"


def test_run_uninstall_local_requires_confirmation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "styxctl.uninstall.collect_inventory",
        lambda: _base_inventory(interface_names=["Styx"]),
    )
    report, code = run_uninstall_local(dry_run=False, yes=False)
    assert code == 0
    assert report["status"] == "CONFIRMATION_REQUIRED"
    assert report["pending_count"] >= 1


def test_uninstall_plan_local_cli(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("styxctl.uninstall.collect_inventory", _base_inventory)
    result = runner.invoke(app, ["uninstall", "plan", "local"])
    assert result.exit_code == 0
    assert "Styx Uninstall Plan" in result.stdout
    assert "dry-run" in result.stdout


def test_uninstall_apply_local_cli_nothing_to_do(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("styxctl.uninstall.collect_inventory", _base_inventory)
    result = runner.invoke(app, ["uninstall", "apply", "local"])
    assert result.exit_code == 0
    assert "Styx Uninstall Plan" in result.stdout


def test_uninstall_local_cli_confirm_no(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "styxctl.uninstall.collect_inventory",
        lambda: _base_inventory(interface_names=["Styx"]),
    )
    result = runner.invoke(app, ["uninstall", "local"], input="n\n")
    assert result.exit_code == 0
    assert "No changes were made" in result.stdout


def test_uninstall_in_help(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "uninstall" in result.stdout
