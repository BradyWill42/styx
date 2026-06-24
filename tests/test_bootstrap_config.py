"""Tests for bootstrap-mode config enrichment."""

from __future__ import annotations

from unittest.mock import patch

from styxctl.bootstrap_config import (
    BOOTSTRAP_SSH_PORT,
    bootstrap_mode,
    dns_publish_enabled,
    enrich_operational_config,
    minimal_runners_config,
)
from styxctl.config import resolve_config, validate_config
from styxctl.nodes import parse_nodes

from tests.support import make_inventory


def test_bootstrap_mode_when_cluster_bootstrap_true():
    config = {"cluster": {"bootstrap": True}, "dns": {"provider": "duckdns"}}
    assert bootstrap_mode(config) is True


def test_bootstrap_mode_when_dns_missing():
    assert bootstrap_mode({"cluster": {"name": "styx"}}) is True


def test_bootstrap_mode_false_when_duckdns_configured():
    config = {"dns": {"provider": "duckdns", "domain": "duckdns.org"}}
    assert bootstrap_mode(config) is False
    assert dns_publish_enabled(config) is True


def test_bootstrap_ssh_port_is_admin_port():
    assert BOOTSTRAP_SSH_PORT == 22


def test_minimal_runners_config_has_three_nodes():
    config = minimal_runners_config()
    nodes = parse_nodes(resolve_config(config))
    assert [node.name for node in nodes] == ["pegasus", "atlas", "thor"]
    assert bootstrap_mode(resolve_config(config)) is True


def test_enrich_operational_config_fills_local_public_ipv4():
    config = resolve_config(minimal_runners_config())
    inventory = make_inventory(
        hostname="pegasus",
        primary_lan_ip="192.168.1.10",
        bootstrap_ipv4="192.168.1.10",
    )

    with (
        patch("styxctl.bootstrap_config.detect_public_ipv4", return_value="203.0.113.10"),
        patch("styxctl.bootstrap_config.detect_public_ipv6", return_value="2001:db8::1"),
        patch("styxctl.bootstrap_config.discover_remote_public_ipv4", return_value=None),
        patch("styxctl.bootstrap_config.discover_remote_public_ipv6", return_value=None),
        patch("styxctl.bootstrap_config.discover_remote_lan_ipv4", return_value=None),
    ):
        enriched = enrich_operational_config(config, inventory)

    pegasus = next(node for node in parse_nodes(enriched) if node.name == "pegasus")
    assert pegasus.public_ipv4 == "203.0.113.10"
    assert pegasus.public_ipv6 == "2001:db8::1"
    assert pegasus.lan_ip == "192.168.1.10"


def test_enrich_operational_config_discovers_remote_public_ipv4():
    config = resolve_config(minimal_runners_config())
    inventory = make_inventory(
        hostname="pegasus",
        primary_lan_ip="192.168.1.10",
        bootstrap_ipv4="192.168.1.10",
    )

    with (
        patch("styxctl.bootstrap_config.detect_public_ipv4", return_value="203.0.113.10"),
        patch("styxctl.bootstrap_config.detect_public_ipv6", return_value="2001:db8::1"),
        patch(
            "styxctl.bootstrap_config.discover_remote_public_ipv4",
            side_effect=lambda name, _user: {"atlas": "203.0.113.10", "thor": "198.51.100.5"}.get(name),
        ),
        patch(
            "styxctl.bootstrap_config.discover_remote_public_ipv6",
            side_effect=lambda name, _user: {"atlas": "2001:db8::1", "thor": "2001:db8::2"}.get(name),
        ),
        patch(
            "styxctl.bootstrap_config.discover_remote_lan_ipv4",
            side_effect=lambda name, _user: {"atlas": "192.168.1.11"}.get(name),
        ),
    ):
        enriched = enrich_operational_config(config, inventory)

    by_name = {node.name: node for node in parse_nodes(enriched)}
    assert by_name["atlas"].public_ipv4 == "203.0.113.10"
    assert by_name["atlas"].public_ipv6 == "2001:db8::1"
    assert by_name["atlas"].lan_ip == "192.168.1.11"
    assert by_name["thor"].public_ipv4 == "198.51.100.5"
    assert by_name["thor"].public_ipv6 == "2001:db8::2"


def test_validate_minimal_bootstrap_config_without_hostname_errors():
    config = resolve_config(minimal_runners_config())
    inventory = make_inventory(
        hostname="pegasus",
        primary_lan_ip="192.168.1.10",
        bootstrap_ipv4="192.168.1.10",
    )

    with (
        patch("styxctl.bootstrap_config.detect_public_ipv4", return_value="203.0.113.10"),
        patch("styxctl.bootstrap_config.detect_public_ipv6", return_value="2001:db8::1"),
        patch(
            "styxctl.bootstrap_config.discover_remote_public_ipv4",
            side_effect=lambda name, _user: {"atlas": "203.0.113.10", "thor": "198.51.100.5"}.get(name),
        ),
        patch(
            "styxctl.bootstrap_config.discover_remote_public_ipv6",
            side_effect=lambda name, _user: {"atlas": "2001:db8::1", "thor": "2001:db8::2"}.get(name),
        ),
        patch(
            "styxctl.bootstrap_config.discover_remote_lan_ipv4",
            side_effect=lambda name, _user: {"atlas": "192.168.1.11"}.get(name),
        ),
    ):
        issues = validate_config(config, inventory=inventory)

    assert not any(issue.level == "error" for issue in issues)
    assert not any("hostname" in issue.message and issue.level == "error" for issue in issues)
