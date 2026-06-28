"""Pure config resolution/validation tests — no inventory, no cluster, no pithor."""

from styxctl.config import resolve_config, validate_config
from styxctl.nodes import parse_nodes, pistyx_holder, validate_nodes


def _base_config():
    # distinct public_ipv4 => two single-node sites (no colocation), so validate_config is clean
    # without an inventory to auto-detect IPs.
    return {
        "cluster": {"name": "styx"},
        "nodes": [
            {"name": "pegasus", "role": "init-server", "hostname": "pipegasus.duckdns.org", "public_ipv4": "203.0.113.1"},
            {"name": "hydra", "role": "agent", "hostname": "pihydra.duckdns.org", "public_ipv4": "203.0.113.2"},
        ],
    }


def test_resolve_injects_defaults_and_mesh_ips():
    cfg = resolve_config(_base_config())
    assert cfg["network"]["ipv4_supernet"] == "10.0.0.0/14"
    assert cfg["egress"]["port"] == 47801
    assert cfg["nodes"][0]["ipv4"] == "10.0.0.1"   # auto-assigned flat mesh IP


def test_valid_config_has_no_errors():
    issues = validate_config(_base_config())
    assert not [i for i in issues if i.level == "error"]


def test_egress_port_must_differ_from_wireguard_port():
    cfg = _base_config()
    cfg["wireguard"] = {"interface": "Styx", "port": 47800}
    cfg["egress"] = {"interface": "StyxEgress", "port": 47800, "hostname": "pistyx.duckdns.org"}
    issues = validate_config(cfg)
    assert any(i.level == "error" and "egress" in i.path for i in issues)


def test_pistyx_holder_defaults_to_init_server():
    cfg = resolve_config(_base_config())
    nodes = parse_nodes(cfg)
    assert pistyx_holder(cfg, nodes).name == "pegasus"


def test_pistyx_holder_follows_current_host():
    cfg = resolve_config({**_base_config(), "pistyx": {"current_host": "hydra"}})
    nodes = parse_nodes(cfg)
    assert pistyx_holder(cfg, nodes).name == "hydra"


def test_colocated_election_leader_validation_has_no_toggle_dependency():
    cfg = resolve_config(
        {
            "cluster": {"name": "styx"},
            "nodes": [
                {
                    "name": "pegasus",
                    "role": "init-server",
                    "hostname": "pipegasus.duckdns.org",
                    "public_ipv4": "203.0.113.1",
                },
                {
                    "name": "hydra",
                    "role": "agent",
                    "hostname": "pihydra.duckdns.org",
                    "public_ipv4": "203.0.113.2",
                },
                {
                    "name": "atlas",
                    "role": "agent",
                    "hostname": "piatlas.duckdns.org",
                    "public_ipv4": "203.0.113.2",
                },
            ],
        }
    )

    assert validate_nodes(parse_nodes(cfg), cfg, election_leader="hydra") == []
