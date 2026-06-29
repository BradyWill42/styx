"""Distributed-cluster guarantees — never single-server, never node-local storage. Pure, no cluster."""

from styxctl.config import resolve_config
from styxctl.k3s_cluster import k3s_install_spec
from styxctl.nodes import parse_nodes, server_role_count, validate_nodes_warnings


def _nodes(node_list):
    return parse_nodes(resolve_config({"cluster": {"name": "styx"}, "nodes": node_list}))


def test_server_role_count_is_control_plane_only():
    nodes = _nodes([
        {"name": "pegasus", "role": "init-server", "public_ipv4": "203.0.113.1"},
        {"name": "hydra", "role": "server", "public_ipv4": "203.0.113.2"},
        {"name": "kraken", "role": "agent", "public_ipv4": "203.0.113.3"},
    ])
    assert server_role_count(nodes) == 2


def test_single_server_cluster_warns():
    nodes = _nodes([
        {"name": "pegasus", "role": "init-server", "public_ipv4": "203.0.113.1"},
        {"name": "kraken", "role": "agent", "public_ipv4": "203.0.113.3"},
    ])
    warns = validate_nodes_warnings(nodes)
    assert any("server-role" in w for w in warns)


def test_init_server_uses_etcd_and_disables_local_storage():
    nodes = _nodes([
        {"name": "pegasus", "role": "init-server", "public_ipv4": "203.0.113.1"},
        {"name": "hydra", "role": "server", "public_ipv4": "203.0.113.2"},
    ])
    init = next(n for n in nodes if n.role == "init-server")
    _env, args, _display = k3s_install_spec({"cluster": {"name": "styx"}}, init, all_nodes=nodes)
    assert "--cluster-init" in args        # embedded etcd, distributed datastore
    assert "--disable" in args and "local-storage" in args   # no node-local PV provisioner


def test_server_node_also_disables_local_storage():
    nodes = _nodes([
        {"name": "pegasus", "role": "init-server", "public_ipv4": "203.0.113.1"},
        {"name": "hydra", "role": "server", "public_ipv4": "203.0.113.2"},
    ])
    server = next(n for n in nodes if n.role == "server")
    _env, args, _display = k3s_install_spec({"cluster": {"name": "styx"}}, server, all_nodes=nodes)
    assert "local-storage" in " ".join(args)


def test_agent_does_not_disable_local_storage():
    nodes = _nodes([
        {"name": "pegasus", "role": "init-server", "public_ipv4": "203.0.113.1"},
        {"name": "kraken", "role": "agent", "public_ipv4": "203.0.113.3"},
    ])
    agent = next(n for n in nodes if n.role == "agent")
    _env, args, _display = k3s_install_spec({"cluster": {"name": "styx"}}, agent, all_nodes=nodes)
    assert "local-storage" not in " ".join(args)
