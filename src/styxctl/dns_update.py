"""DuckDNS dynamic IP updates."""

from __future__ import annotations

import os
import re
from typing import Any, Callable
from urllib.error import URLError
from urllib.request import urlopen

from .inventory import safe_run
from .nodes import ClusterNode, node_hostname, node_subdomain, parse_nodes

_DUCKDNS_RESPONSE = re.compile(r"^(OK|KO|BADTOKEN|UPDATED|NOCHANGE|DONATE|TOO FREQUENT)", re.I)
_PUBLIC_IP_DETECT_CMD = "curl -4 -fsS https://api.ipify.org || curl -4 -fsS https://icanhazip.com"

RunResult = tuple[bool, str]
SshRunner = Callable[..., RunResult]


def duckdns_token(config: dict[str, Any]) -> str | None:
    dns = config.get("dns")
    if not isinstance(dns, dict):
        return None
    token_env = dns.get("token_env")
    if isinstance(token_env, str) and token_env.strip():
        value = os.environ.get(token_env.strip())
        if value:
            return value.strip()
    token = dns.get("token")
    if isinstance(token, str) and token.strip():
        return token.strip()
    return None


def detect_public_ipv4() -> str | None:
    for url in (
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ):
        try:
            with urlopen(url, timeout=5) as response:
                text = response.read().decode("utf-8").strip()
        except (OSError, URLError, TimeoutError):
            continue
        if text and "." in text:
            return text.split()[0]
    result = safe_run("curl_public_ip", ["curl", "-4", "-fsS", "https://api.ipify.org"], timeout=8.0)
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    return None


def detect_public_ipv4_remote(
    target: str,
    *,
    port: int = 47810,
    runner: SshRunner,
) -> str | None:
    ok, detail = runner(target, _PUBLIC_IP_DETECT_CMD, port=port)
    if not ok:
        return None
    candidate = detail.strip().split()[0] if detail.strip() else ""
    if candidate and "." in candidate:
        return candidate
    return None


def update_duckdns(
    *,
    subdomain: str,
    token: str,
    ipv4: str | None = None,
) -> tuple[bool, str]:
    query = f"https://www.duckdns.org/update?domains={subdomain}&token={token}"
    if ipv4:
        query += f"&ip={ipv4}"
    try:
        with urlopen(query, timeout=10) as response:
            body = response.read().decode("utf-8").strip()
    except (OSError, URLError, TimeoutError) as exc:
        return False, str(exc)

    if _DUCKDNS_RESPONSE.match(body):
        return body.upper().startswith("OK"), body
    return False, body or "unknown DuckDNS response"


def refresh_node_duckdns(
    config: dict[str, Any],
    node: ClusterNode,
    *,
    ipv4: str | None = None,
) -> tuple[bool, str]:
    dns = config.get("dns")
    if not isinstance(dns, dict) or dns.get("provider") != "duckdns":
        return False, "dns.provider is not duckdns"

    hostname = node_hostname(config, node)
    if not hostname:
        return False, f"no DuckDNS hostname configured for node {node.name}"

    token = duckdns_token(config)
    if not token:
        return False, "DuckDNS token not configured (set dns.token_env or dns.token)"

    public_ip = ipv4 or detect_public_ipv4()
    if not public_ip:
        return False, "could not detect current public IPv4 for DuckDNS update"

    subdomain = node_subdomain(hostname, config)
    return update_duckdns(subdomain=subdomain, token=token, ipv4=public_ip)


def refresh_local_node_duckdns(config: dict[str, Any], inventory_hostname: str) -> tuple[bool, str]:
    nodes = parse_nodes(config)
    for node in nodes:
        if node.name == inventory_hostname:
            return refresh_node_duckdns(config, node)
    for node in nodes:
        host = node_hostname(config, node)
        if host and inventory_hostname in {node.name, host.split(".", 1)[0]}:
            return refresh_node_duckdns(config, node)
    return False, f"no configured node matches local hostname {inventory_hostname}"
