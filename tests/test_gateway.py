"""Tests for DuckDNS and gateway port configuration."""

from __future__ import annotations

from styxctl.config import load_config, validate_config
from styxctl.nodes import node_hostname, node_subdomain
from styxctl.gateway import k3s_gateway_listen_args, k3s_join_url, parse_gateway_ports
from styxctl.k3s_cluster import build_cluster_plan
from styxctl.nodes import parse_nodes

from tests.support import EXAMPLE_CONFIG_PATH


def test_parse_gateway_ports_defaults():
    ports = parse_gateway_ports({})
    assert ports.ssh == 47810
    assert ports.k3s_api == 47811


def test_node_hostname_from_dns_mapping():
    config = load_config(EXAMPLE_CONFIG_PATH)
    nodes = parse_nodes(config)
    by_name = {node.name: node for node in nodes}
    assert node_hostname(config, by_name["node-init"]) == "styx-lab-init.duckdns.org"
    assert node_hostname(config, by_name["node-server"]) == "styx-lab-server.duckdns.org"
    assert node_subdomain("styx-lab-server.duckdns.org", config) == "styx-lab-server"


def test_build_cluster_plan_uses_public_ipv4_bootstrap():
    config = load_config(EXAMPLE_CONFIG_PATH)
    plan = build_cluster_plan(config)
    assert plan.join_url == "https://203.0.113.10:47811"
    init_plan = plan.nodes[0]
    assert init_plan.target_host == "203.0.113.10"
    assert init_plan.ssh_port == 47810
    assert "203.0.113.10" in init_plan.tls_sans
    assert "styx-lab-init.duckdns.org" in init_plan.tls_sans


def test_validate_gateway_ports_in_reserved_range(tmp_path):
    config = load_config(EXAMPLE_CONFIG_PATH)
    config["gateway"] = {"ssh_port": 47810, "k3s_api_port": 47811}
    issues = validate_config(config)
    assert not any(issue.path == "gateway" and issue.level == "error" for issue in issues)


def test_k3s_join_url_helper():
    ports = parse_gateway_ports({"gateway": {"ssh_port": 47810, "k3s_api_port": 47811}})
    assert k3s_join_url("styx-lab-init.duckdns.org", ports) == "https://styx-lab-init.duckdns.org:47811"


def test_k3s_gateway_listen_args():
    config = load_config(EXAMPLE_CONFIG_PATH)
    args = k3s_gateway_listen_args(config, server_role=True)
    assert args == ["--https-listen-port", "47811"]
    assert k3s_gateway_listen_args(config, server_role=False) == []
