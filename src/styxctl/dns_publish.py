"""MVP3: per-site DuckDNS publishers.

Each *site* (a group of nodes sharing a public IP) gets ONE updater Deployment, pinned to
that site's leader node, that keeps the site's DuckDNS names pointed at the site's public
IPv4+IPv6 (the leader's WAN — its pod egress). Sites are derived by resolving each node's
configured `hostname` (its DuckDNS name) to a public IP and grouping. The DuckDNS token is
read from $DUCKDNS_TOKEN at apply time into a Secret — never written to styx.yaml.

The floating `pistyx` ("quickest site") is the deferred dynamic part and is NOT handled here.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STYX_NAMESPACE = "styx-system"
DUCKDNS_APP = "styx-duckdns"
DUCKDNS_SECRET = "styx-duckdns-token"
DEFAULT_INTERVAL_SECONDS = 300
DEFAULT_UPDATER_IMAGE = "curlimages/curl:latest"
DEFAULT_TOKEN_ENV = "DUCKDNS_TOKEN"
_TOKEN_PLACEHOLDER = "<set at apply time from $DUCKDNS_TOKEN — not shown>"

RunResult = tuple[bool, str]


@dataclass(slots=True)
class DnsPublishSettings:
    interval_seconds: int
    token_env: str
    image: str


def parse_dns_settings(config: dict[str, Any]) -> DnsPublishSettings | None:
    """Return DuckDNS publish settings, or None when no ``dns:`` block is configured."""
    dns = config.get("dns")
    if not isinstance(dns, dict):
        return None

    interval = dns.get("interval_seconds", DEFAULT_INTERVAL_SECONDS)
    if not isinstance(interval, int) or interval <= 0:
        interval = DEFAULT_INTERVAL_SECONDS

    token_env = dns.get("token_env")
    token_env = token_env.strip() if isinstance(token_env, str) and token_env.strip() else DEFAULT_TOKEN_ENV

    image = dns.get("image")
    image = image.strip() if isinstance(image, str) and image.strip() else DEFAULT_UPDATER_IMAGE

    return DnsPublishSettings(interval_seconds=interval, token_env=token_env, image=image)


def _subdomain(hostname: str | None) -> str | None:
    """'pipegasus.duckdns.org' -> 'pipegasus' (the DuckDNS subdomain to update)."""
    if not isinstance(hostname, str) or not hostname.strip():
        return None
    return hostname.strip().split(".", 1)[0]


@dataclass(slots=True)
class SitePublisher:
    leader: str          # k8s node name (== styx node name) to pin the updater to
    domains: list[str]   # DuckDNS subdomains for this site


def site_publishers(config: dict[str, Any]) -> list[SitePublisher]:
    """Group nodes into sites by resolved public IP; one publisher per site, on its leader."""
    from .network_detect import resolve_dns_ipv4
    from .nodes import (
        node_hostname,
        parse_nodes,
        site_entrypoint_for,
        sites_by_public_ip,
    )

    nodes = parse_nodes(config)
    # Resolve each node's DuckDNS hostname to a public IP so colocated nodes group together.
    for node in nodes:
        if not node.public_ipv4:
            resolved = resolve_dns_ipv4(node_hostname(config, node) or "")
            if resolved:
                node.public_ipv4 = resolved

    publishers: list[SitePublisher] = []
    for _public_ip, site_nodes in sites_by_public_ip(nodes).items():
        leader = site_entrypoint_for(site_nodes[0], nodes) or site_nodes[0]
        domains: list[str] = []
        for node in site_nodes:
            sub = _subdomain(node_hostname(config, node))
            if sub and sub not in domains:
                domains.append(sub)
        if domains:
            publishers.append(SitePublisher(leader=leader.name, domains=sorted(domains)))
    publishers.sort(key=lambda p: p.leader)
    return publishers


_NS_AND_SECRET = """\
apiVersion: v1
kind: Namespace
metadata:
  name: __NAMESPACE__
  labels:
    app.kubernetes.io/managed-by: styxctl
---
apiVersion: v1
kind: Secret
metadata:
  name: __SECRET__
  namespace: __NAMESPACE__
  labels:
    app.kubernetes.io/managed-by: styxctl
type: Opaque
stringData:
  token: "__TOKEN__"
"""

_DEPLOYMENT = """\
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: __NAME__
  namespace: __NAMESPACE__
  labels:
    app.kubernetes.io/name: __APP__
    app.kubernetes.io/managed-by: styxctl
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/instance: __NAME__
  template:
    metadata:
      labels:
        app.kubernetes.io/name: __APP__
        app.kubernetes.io/instance: __NAME__
    spec:
      nodeSelector:
        kubernetes.io/hostname: "__LEADER__"
      containers:
        - name: duckdns
          image: "__IMAGE__"
          command: ["/bin/sh", "-c"]
          args:
            - |
              echo "styx-duckdns: site leader __LEADER__ publishing ${DUCKDNS_DOMAINS} every ${DUCKDNS_INTERVAL}s"
              while true; do
                V4="$(curl -4 -fsS https://ifconfig.me 2>/dev/null || true)"
                V6="$(curl -6 -fsS https://ifconfig.me 2>/dev/null || true)"
                if curl -fsS "https://www.duckdns.org/update?domains=${DUCKDNS_DOMAINS}&token=${DUCKDNS_TOKEN}&ip=${V4}&ipv6=${V6}" | grep -q OK; then
                  echo "styx-duckdns: updated ${DUCKDNS_DOMAINS} -> ${V4} ${V6}"
                else
                  echo "styx-duckdns: update FAILED for ${DUCKDNS_DOMAINS}"
                fi
                sleep "${DUCKDNS_INTERVAL}"
              done
          env:
            - name: DUCKDNS_DOMAINS
              value: "__DOMAINS__"
            - name: DUCKDNS_INTERVAL
              value: "__INTERVAL__"
            - name: DUCKDNS_TOKEN
              valueFrom:
                secretKeyRef:
                  name: __SECRET__
                  key: token
          resources:
            requests:
              cpu: 10m
              memory: 16Mi
            limits:
              memory: 48Mi
"""


def _fill(template: str, repl: dict[str, str]) -> str:
    for marker, value in repl.items():
        template = template.replace(marker, value)
    return template


def render_duckdns_manifest(
    settings: DnsPublishSettings,
    publishers: list[SitePublisher],
    *,
    token: str | None,
) -> str:
    """Render Namespace + Secret + one Deployment per site (pinned to that site's leader)."""
    parts = [_fill(_NS_AND_SECRET, {
        "__NAMESPACE__": STYX_NAMESPACE,
        "__SECRET__": DUCKDNS_SECRET,
        "__TOKEN__": token if token is not None else _TOKEN_PLACEHOLDER,
    })]
    for pub in publishers:
        parts.append(_fill(_DEPLOYMENT, {
            "__NAME__": f"{DUCKDNS_APP}-{pub.leader}",
            "__APP__": DUCKDNS_APP,
            "__NAMESPACE__": STYX_NAMESPACE,
            "__SECRET__": DUCKDNS_SECRET,
            "__LEADER__": pub.leader,
            "__IMAGE__": settings.image,
            "__DOMAINS__": ",".join(pub.domains),
            "__INTERVAL__": str(settings.interval_seconds),
        }))
    return "".join(parts)


def _kubectl_apply_local(manifest: str, *, sudo: bool) -> RunResult:
    """Pipe a manifest to ``kubectl apply -f -`` on the local (init-server) node."""
    if shutil.which("kubectl") is None and not (sudo and shutil.which("sudo")):
        return False, "kubectl not found on PATH"
    command = (["sudo"] if sudo else []) + ["kubectl", "apply", "-f", "-"]
    try:
        completed = subprocess.run(
            command, check=False, input=manifest, capture_output=True, text=True, timeout=120.0
        )
    except subprocess.TimeoutExpired:
        return False, "kubectl apply timed out after 120s"
    except OSError as exc:
        return False, str(exc)
    if completed.returncode == 0:
        return True, (completed.stdout or "applied").strip()
    return False, (completed.stderr or completed.stdout or "").strip() or f"kubectl exit {completed.returncode}"


def deploy_dns(
    *,
    dry_run: bool,
    config_path: str | Path | None = None,
    token: str | None = None,
    sudo: bool = True,
) -> tuple[dict[str, Any], int]:
    """Render (and, unless dry_run, apply) the per-site DuckDNS publishers."""
    from .config import find_config, load_config, resolve_config

    report: dict[str, Any] = {"status": "OK", "dry_run": dry_run, "actions": []}

    candidate = Path(config_path) if config_path is not None else find_config()
    if candidate is None:
        report["status"] = "ERROR"
        report["message"] = "no styx.yaml found"
        return report, 1

    config = resolve_config(load_config(candidate))
    settings = parse_dns_settings(config)
    if settings is None:
        report["status"] = "ERROR"
        report["message"] = "no dns: block in styx.yaml — add a `dns:` block to enable DuckDNS publishing"
        return report, 1

    publishers = site_publishers(config)
    if not publishers:
        report["status"] = "ERROR"
        report["message"] = "no sites with resolvable DuckDNS hostnames found — set node hostname: values"
        return report, 1

    report["sites"] = [{"leader": p.leader, "domains": p.domains} for p in publishers]
    report["namespace"] = STYX_NAMESPACE
    report["interval_seconds"] = settings.interval_seconds

    if dry_run:
        report["manifest"] = render_duckdns_manifest(settings, publishers, token=None)
        report["actions"].append(
            f"would apply Namespace/{STYX_NAMESPACE}, Secret/{DUCKDNS_SECRET}, and "
            f"{len(publishers)} site publisher Deployment(s)"
        )
        return report, 0

    token = token if token is not None else os.environ.get(settings.token_env)
    if not token:
        report["status"] = "ERROR"
        report["message"] = f"DuckDNS token not set — export ${settings.token_env} before `deploy dns apply`"
        return report, 1

    manifest = render_duckdns_manifest(settings, publishers, token=token)
    ok, detail = _kubectl_apply_local(manifest, sudo=sudo)
    report["actions"].append(detail)
    if not ok:
        report["status"] = "ERROR"
        report["message"] = detail
        return report, 1

    report["message"] = (
        f"{len(publishers)} site DuckDNS publisher(s) deployed to {STYX_NAMESPACE}"
    )
    return report, 0


def render_dns_report_text(report: dict[str, Any]) -> str:
    """Human-readable rendering of a deploy_dns report."""
    lines: list[str] = []
    status = report.get("status", "OK")
    lines.append(f"=== deploy dns ({'plan' if report.get('dry_run') else 'apply'}) — {status} ===")
    if report.get("message"):
        lines.append(report["message"])
    for site in report.get("sites", []):
        lines.append(f"  site leader {site['leader']}: publishes {', '.join(site['domains'])}")
    if report.get("interval_seconds"):
        lines.append(f"update interval: {report['interval_seconds']}s")
    for action in report.get("actions", []):
        lines.append(f"  - {action}")
    if report.get("manifest"):
        lines.append("")
        lines.append("--- manifest ---")
        lines.append(report["manifest"].rstrip())
    return "\n".join(lines) + "\n"
