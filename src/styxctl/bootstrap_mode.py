"""Bootstrap vs operational-mode detection (no heavy imports)."""

from __future__ import annotations

from typing import Any


def bootstrap_mode(config: dict[str, Any]) -> bool:
    """True when DNS publish is deferred (pre-DuckDNS bootstrap)."""
    cluster = config.get("cluster")
    if isinstance(cluster, dict) and cluster.get("bootstrap") is True:
        return True
    dns = config.get("dns")
    if dns is None:
        return True
    if isinstance(dns, dict):
        provider = dns.get("provider")
        if provider in (None, "", "none", "disabled"):
            return True
    return False


def dns_publish_enabled(config: dict[str, Any]) -> bool:
    return not bootstrap_mode(config)
