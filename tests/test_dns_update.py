"""Tests for DuckDNS updates and connectivity cutover."""

from __future__ import annotations

from styxctl.config import load_config
from styxctl.dns_update import refresh_node_duckdns
from styxctl.k3s_cluster import assess_cluster_nodes, refresh_cluster_duckdns
from styxctl.nodes import (
    CONNECTIVITY_DUCKDNS,
    duckdns_hostnames_resolve,
    node_connectivity_host,
    parse_nodes,
)

from tests.support import EXAMPLE_CONFIG_PATH


def test_node_connectivity_host_uses_duckdns_after_bootstrap(monkeypatch):
    config = load_config(EXAMPLE_CONFIG_PATH)
    nodes = parse_nodes(config)
    node = nodes[0]

    monkeypatch.setattr("styxctl.nodes.resolve_hostname", lambda host: "203.0.113.99")

    assert node_connectivity_host(config, node, mode=CONNECTIVITY_DUCKDNS) == "styx-lab-init.duckdns.org"
    assert node.resolved_ipv4(config, mode=CONNECTIVITY_DUCKDNS) == "203.0.113.99"


def test_refresh_node_duckdns_uses_explicit_ipv4(monkeypatch):
    config = load_config(EXAMPLE_CONFIG_PATH)
    nodes = parse_nodes(config)
    node = nodes[0]
    monkeypatch.setenv("DUCKDNS_TOKEN", "test-token")
    monkeypatch.setattr(
        "styxctl.dns_update.update_duckdns",
        lambda **kwargs: (True, "OK"),
    )

    ok, detail = refresh_node_duckdns(config, node, ipv4="198.51.100.10")
    assert ok is True
    assert detail == "OK"


def test_refresh_cluster_duckdns_detects_remote_public_ip(monkeypatch):
    config = load_config(EXAMPLE_CONFIG_PATH)
    nodes = parse_nodes(config)

    def fake_ssh(target: str, command: str, **kwargs):
        if "ipify" in command or "icanhazip" in command:
            return True, "198.51.100.20"
        return True, "active"

    monkeypatch.setenv("DUCKDNS_TOKEN", "test-token")
    monkeypatch.setattr(
        "styxctl.dns_update.update_duckdns",
        lambda **kwargs: (True, "OK") if kwargs.get("ipv4") else (False, "missing ip"),
    )

    messages = refresh_cluster_duckdns(
        config,
        nodes,
        ssh_user="ubuntu",
        runner=fake_ssh,
    )
    assert len(messages) == 3
    assert all("published" in message for message in messages)


def test_assess_cluster_nodes_defaults_to_duckdns(monkeypatch):
    config = load_config(EXAMPLE_CONFIG_PATH)
    nodes = parse_nodes(config)
    monkeypatch.setattr("styxctl.nodes.duckdns_hostnames_resolve", lambda *_args, **_kwargs: True)

    def fake_ssh(target: str, command: str, **kwargs):
        if "kubectl get nodes" in command:
            return True, '{"items":[{"metadata":{"name":"node-init"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}'
        return True, "active"

    health = assess_cluster_nodes(config, ssh_user="ubuntu", runner=fake_ssh)
    assert health["connectivity_mode"] == CONNECTIVITY_DUCKDNS
    assert health["join_url"] == "https://styx-lab-init.duckdns.org:47811"
    assert health["nodes"][0]["connectivity_host"] == "styx-lab-init.duckdns.org"


def test_duckdns_hostnames_resolve_requires_all_nodes(monkeypatch):
    config = load_config(EXAMPLE_CONFIG_PATH)
    nodes = parse_nodes(config)

    def resolve(host: str) -> str | None:
        return "203.0.113.10" if host.endswith("init.duckdns.org") else None

    monkeypatch.setattr("styxctl.nodes.resolve_hostname", resolve)
    assert duckdns_hostnames_resolve(config, nodes) is False
