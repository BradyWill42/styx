"""Bootstrap-mode detection for auto IP discovery (external DNS is MVP3)."""

from __future__ import annotations

from typing import Any


def bootstrap_mode(config: dict[str, Any]) -> bool:
    """True when styxctl should auto-detect IPs (default until explicit IPs are set)."""
    cluster = config.get("cluster")
    if isinstance(cluster, dict) and cluster.get("bootstrap") is False:
        return False
    return True
