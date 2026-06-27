"""Bootstrap-mode detection for auto IP discovery (external DNS is MVP3)."""

from __future__ import annotations

from typing import Any


def bootstrap_mode(config: dict[str, Any]) -> bool:
    """Always True: styxctl always auto-detects local IPs and resolves peers by DuckDNS name.

    The `cluster.bootstrap` opt-out was removed — auto-discovery is the only supported mode.
    """
    return True
