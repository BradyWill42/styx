"""Three-node cluster connectivity and uninstall simulation tests."""

from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from styxctl.cli import app
from styxctl.install import run_install_cluster
from styxctl.k3s_cluster import build_cluster_plan
from styxctl.nodes import identify_local_node, node_effective_lan_ip, parse_nodes, validate_nodes
from styxctl.uninstall import apply_cluster_uninstall_plan, build_cluster_uninstall_plan

from tests.support import example_config_text, make_inventory

runner = CliRunner()


def _three_node_config_without_lan_ip() -> dict:
    config = yaml.safe_load(example_config_text())
    for node in config["nodes"]:
        node.pop("lan_ip", None)
    return config


def _node_inventory(node_name: str, *, lan_ip: str, mesh_ipv4: str, public_ipv4: str):
    return make_inventory(
        hostname=node_name,
        fqdn=f"{node_name}.local",
        bootstrap_ipv4=lan_ip,
        primary_lan_ip=lan_ip,
        network_interfaces=[f"eth0 UP {lan_ip}/24"],
        interface_names=[],
        wireguard_interfaces=[],
        detected_binaries={"k3s": "/usr/local/bin/k3s", "curl": "/usr/bin/curl"},
    )


def test_validate_three_node_config_without_lan_ip_when_local_node_detectable(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = _three_node_config_without_lan_ip()
    config_path = tmp_path / "styx.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    nodes = parse_nodes(config)
    inventory = _node_inventory("node-init", lan_ip="192.168.1.10", mesh_ipv4="10.0.0.1", public_ipv4="203.0.113.10")
    local_node = identify_local_node(nodes, inventory, config)

    assert local_node is not None
    assert local_node.name == "node-init"
    assert node_effective_lan_ip(local_node, inventory=inventory, local_node=local_node) == "192.168.1.10"

    errors = validate_nodes(nodes, config, inventory=inventory, local_node=local_node)
    assert not any("nodes.node-init" in error and "lan_ip is required" in error for error in errors)


def test_build_cluster_plan_targets_all_three_nodes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = _three_node_config_without_lan_ip()
    config_path = tmp_path / "styx.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    nodes = parse_nodes(config)
    inventory = _node_inventory("node-init", lan_ip="192.168.1.10", mesh_ipv4="10.0.0.1", public_ipv4="203.0.113.10")
    local_node = identify_local_node(nodes, inventory, config)
    cluster_plan = build_cluster_plan(config, local_node=local_node, inventory=inventory)

    assert len(cluster_plan.nodes) == 3
    assert {item.node.name for item in cluster_plan.nodes} == {"node-init", "node-server", "node-agent"}


def test_run_install_cluster_reaches_all_three_nodes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = _three_node_config_without_lan_ip()
    config_path = tmp_path / "styx.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    inventory = _node_inventory("node-init", lan_ip="192.168.1.10", mesh_ipv4="10.0.0.1", public_ipv4="203.0.113.10")
    monkeypatch.setattr("styxctl.install.collect_inventory", lambda: inventory)
    monkeypatch.setattr("styxctl.install._k3s_install_local", lambda *args, **kwargs: (True, "installed"))

    seen_targets: list[str] = []

    def fake_ssh(target: str, command: str, **kwargs):
        seen_targets.append(target)
        if "node-token" in command:
            return True, "test-token"
        if "kubectl get nodes" in command:
            return True, '{"items":[{"metadata":{"name":"node-init"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}'
        return True, "active"

    monkeypatch.setattr("styxctl.install._run_ssh_command", fake_ssh)
    monkeypatch.setattr("styxctl.k3s_cluster.refresh_node_duckdns", lambda config, node: (False, "mocked"))

    report, exit_code = run_install_cluster(
        dry_run=False,
        yes=True,
        config_path=config_path,
        runner=fake_ssh,
    )

    assert report["cluster"] is not None
    assert len(seen_targets) >= 2
    assert any("203.0.113.11" in target for target in seen_targets)
    assert any("203.0.113.12" in target for target in seen_targets)
    assert exit_code in (0, 1)


def test_cluster_uninstall_plan_includes_all_three_nodes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = _three_node_config_without_lan_ip()
    config_path = tmp_path / "styx.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    inventory = _node_inventory("node-init", lan_ip="192.168.1.10", mesh_ipv4="10.0.0.1", public_ipv4="203.0.113.10")
    monkeypatch.setattr("styxctl.uninstall._detect_k3s_uninstall_script", lambda: None)
    plan = build_cluster_uninstall_plan(config_path=config_path, inventory=inventory)

    assert len(plan.nodes) == 3
    assert sum(1 for node in plan.nodes if node.local_execution) == 1


def test_apply_cluster_uninstall_plan_runs_ssh_for_remote_nodes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = _three_node_config_without_lan_ip()
    config_path = tmp_path / "styx.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    inventory = _node_inventory("node-init", lan_ip="192.168.1.10", mesh_ipv4="10.0.0.1", public_ipv4="203.0.113.10")
    monkeypatch.setattr("styxctl.uninstall._detect_k3s_uninstall_script", lambda: None)
    monkeypatch.setattr("styxctl.uninstall.apply_uninstall_plan", lambda plan, inventory=None: plan)

    seen_targets: list[str] = []

    def fake_ssh(target, command, **kwargs):
        seen_targets.append(target)
        return True, "ok"

    plan = build_cluster_uninstall_plan(config_path=config_path, inventory=inventory)
    applied = apply_cluster_uninstall_plan(plan, config_path=config_path, inventory=inventory, runner=fake_ssh)

    assert len(seen_targets) == 2
    assert all(node.status == "removed" for node in applied.nodes)
    assert any("203.0.113.11" in target for target in seen_targets)
    assert any("203.0.113.12" in target for target in seen_targets)


def test_uninstall_plan_cluster_cli(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "styx.yaml"
    config_path.write_text(yaml.safe_dump(_three_node_config_without_lan_ip()), encoding="utf-8")
    monkeypatch.setattr("styxctl.uninstall.collect_inventory", lambda: _node_inventory(
        "node-init", lan_ip="192.168.1.10", mesh_ipv4="10.0.0.1", public_ipv4="203.0.113.10"
    ))
    monkeypatch.setattr("styxctl.uninstall._detect_k3s_uninstall_script", lambda: None)

    result = runner.invoke(app, ["uninstall", "plan", "cluster"])
    assert result.exit_code == 0
    assert "Styx Cluster Uninstall Plan" in result.stdout
    assert "node-init" in result.stdout
    assert "node-server" in result.stdout
    assert "node-agent" in result.stdout
