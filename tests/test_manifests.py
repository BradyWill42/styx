"""The rendered k8s manifests must be valid YAML — block-scalar shell scripts are easy to mis-indent.
All pure render, no kubectl/cluster/pithor."""

import yaml

from styxctl.cluster_dns import parse_resolver_settings, render_resolver_manifest
from styxctl.dns_publish import DnsPublishSettings, SitePublisher, render_duckdns_manifest
from styxctl.reresolve import parse_reresolve_settings, render_reresolve_manifest


def _kinds(manifest: str) -> list[str]:
    return [doc["kind"] for doc in yaml.safe_load_all(manifest) if isinstance(doc, dict) and "kind" in doc]


def test_resolver_manifest_is_valid_yaml():
    kinds = _kinds(render_resolver_manifest(parse_resolver_settings({})))
    assert "Namespace" in kinds
    assert "ConfigMap" in kinds
    assert kinds.count("DaemonSet") == 2   # resolver + enforcer


def test_resolver_without_force_drops_the_enforcer():
    kinds = _kinds(render_resolver_manifest(parse_resolver_settings({"resolver": {"force": False}})))
    assert kinds.count("DaemonSet") == 1   # resolver only, no resolv.conf enforcer


def test_reresolve_manifest_is_valid_yaml():
    kinds = _kinds(render_reresolve_manifest(parse_reresolve_settings({})))
    assert "DaemonSet" in kinds


def test_duckdns_manifest_is_valid_yaml():
    settings = DnsPublishSettings(interval_seconds=300, token_env="DUCKDNS_TOKEN", image="curlimages/curl:latest")
    publishers = [SitePublisher(leader="pegasus", domains=["pipegasus", "pistyx"])]
    kinds = _kinds(render_duckdns_manifest(settings, publishers, token=None))
    assert "Namespace" in kinds and "Secret" in kinds and "Deployment" in kinds
