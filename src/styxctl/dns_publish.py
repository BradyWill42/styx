"""MVP3: publish cluster DNS to DuckDNS from inside k3s.

A tiny Deployment runs on the init-server node and periodically pings the DuckDNS
update endpoint, keeping the configured names (e.g. the floating ``pistyx``) pointed
at the cluster's WAN IP. DuckDNS auto-detects the source IP, so pinning the pod to
the init-server makes its egress the leader's WAN — no IP plumbing required.

styxctl only needs the DuckDNS *token* at apply time (injected into a Secret from
the ``DUCKDNS_TOKEN`` environment variable); the token is never written to styx.yaml.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .nodes import init_server_node, parse_nodes

STYX_NAMESPACE = "styx-system"
DUCKDNS_DEPLOYMENT = "styx-duckdns"
DUCKDNS_SECRET = "styx-duckdns-token"
DEFAULT_INTERVAL_SECONDS = 300
DEFAULT_UPDATER_IMAGE = "curlimages/curl:latest"
DEFAULT_TOKEN_ENV = "DUCKDNS_TOKEN"
_TOKEN_PLACEHOLDER = "<set at apply time from $DUCKDNS_TOKEN — not shown>"

RunResult = tuple[bool, str]


@dataclass(slots=True)
class DnsPublishSettings:
    """Parsed ``dns:`` block from styx.yaml (DuckDNS provider only in MVP3)."""

    provider: str
    domains: list[str]
    interval_seconds: int
    token_env: str
    image: str
    node: str | None  # k8s hostname to pin the updater to; defaults to the init-server


def parse_dns_settings(config: dict[str, Any]) -> DnsPublishSettings | None:
    """Return DuckDNS publish settings, or None when no ``dns:`` block is configured."""
    dns = config.get("dns")
    if not isinstance(dns, dict):
        return None

    provider = dns.get("provider")
    provider = provider.strip().lower() if isinstance(provider, str) else ""

    raw_domains = dns.get("domains")
    domains: list[str] = []
    if isinstance(raw_domains, list):
        for item in raw_domains:
            if isinstance(item, str) and item.strip():
                domains.append(item.strip())
    elif isinstance(raw_domains, str) and raw_domains.strip():
        domains = [part.strip() for part in raw_domains.split(",") if part.strip()]

    interval = dns.get("interval_seconds", DEFAULT_INTERVAL_SECONDS)
    if not isinstance(interval, int) or interval <= 0:
        interval = DEFAULT_INTERVAL_SECONDS

    token_env = dns.get("token_env")
    token_env = token_env.strip() if isinstance(token_env, str) and token_env.strip() else DEFAULT_TOKEN_ENV

    image = dns.get("image")
    image = image.strip() if isinstance(image, str) and image.strip() else DEFAULT_UPDATER_IMAGE

    node = dns.get("node")
    node = node.strip() if isinstance(node, str) and node.strip() else None

    return DnsPublishSettings(
        provider=provider,
        domains=domains,
        interval_seconds=interval,
        token_env=token_env,
        image=image,
        node=node,
    )


_MANIFEST_TEMPLATE = """\
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
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: __DEPLOYMENT__
  namespace: __NAMESPACE__
  labels:
    app.kubernetes.io/name: __DEPLOYMENT__
    app.kubernetes.io/managed-by: styxctl
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: __DEPLOYMENT__
  template:
    metadata:
      labels:
        app.kubernetes.io/name: __DEPLOYMENT__
    spec:
__NODE_SELECTOR__\
      containers:
        - name: duckdns
          image: "__IMAGE__"
          command: ["/bin/sh", "-c"]
          args:
            - |
              echo "styx-duckdns: publishing ${DUCKDNS_DOMAINS} every ${DUCKDNS_INTERVAL}s"
              while true; do
                if curl -fsS "https://www.duckdns.org/update?domains=${DUCKDNS_DOMAINS}&token=${DUCKDNS_TOKEN}&ip=" | grep -q OK; then
                  echo "styx-duckdns: updated ${DUCKDNS_DOMAINS}"
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


def render_duckdns_manifest(
    settings: DnsPublishSettings,
    *,
    node_hostname: str | None,
    token: str | None,
) -> str:
    """Render the DuckDNS updater manifest. ``token`` None renders a redacted placeholder."""
    if node_hostname:
        node_selector = (
            "      nodeSelector:\n"
            f'        kubernetes.io/hostname: "{node_hostname}"\n'
        )
    else:
        node_selector = ""

    replacements = {
        "__NAMESPACE__": STYX_NAMESPACE,
        "__SECRET__": DUCKDNS_SECRET,
        "__DEPLOYMENT__": DUCKDNS_DEPLOYMENT,
        "__IMAGE__": settings.image,
        "__DOMAINS__": ",".join(settings.domains),
        "__INTERVAL__": str(settings.interval_seconds),
        "__TOKEN__": token if token is not None else _TOKEN_PLACEHOLDER,
        "__NODE_SELECTOR__": node_selector,
    }
    manifest = _MANIFEST_TEMPLATE
    for marker, value in replacements.items():
        manifest = manifest.replace(marker, value)
    return manifest


def _kubectl_apply_local(manifest: str, *, sudo: bool) -> RunResult:
    """Pipe a manifest to ``kubectl apply -f -`` on the local (init-server) node."""
    if shutil.which("kubectl") is None and not (sudo and shutil.which("sudo")):
        return False, "kubectl not found on PATH"
    command = (["sudo"] if sudo else []) + ["kubectl", "apply", "-f", "-"]
    try:
        completed = subprocess.run(
            command,
            check=False,
            input=manifest,
            capture_output=True,
            text=True,
            timeout=120.0,
        )
    except subprocess.TimeoutExpired:
        return False, "kubectl apply timed out after 120s"
    except OSError as exc:
        return False, str(exc)
    detail = (completed.stdout or completed.stderr or "").strip()
    if completed.returncode == 0:
        return True, detail or "applied"
    return False, (completed.stderr or completed.stdout or "").strip() or f"kubectl exit {completed.returncode}"


def deploy_dns(
    *,
    dry_run: bool,
    config_path: str | Path | None = None,
    token: str | None = None,
    sudo: bool = True,
) -> tuple[dict[str, Any], int]:
    """Render (and, unless dry_run, apply) the DuckDNS publish manifest.

    Returns a report dict and an exit code. Designed to run on the init-server,
    where kubectl is configured; applies via local ``kubectl apply -f -``.
    """
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
        report["message"] = (
            "no dns: block in styx.yaml — add `dns: {provider: duckdns, domains: [pistyx]}`"
        )
        return report, 1
    if settings.provider != "duckdns":
        report["status"] = "ERROR"
        report["message"] = f"dns.provider {settings.provider!r} unsupported (MVP3 supports: duckdns)"
        return report, 1
    if not settings.domains:
        report["status"] = "ERROR"
        report["message"] = "dns.domains is empty — list the DuckDNS subdomain(s) to publish, e.g. [pistyx]"
        return report, 1

    nodes = parse_nodes(config)
    init_node = init_server_node(nodes)
    pin_node = settings.node or (init_node.name if init_node else None)

    report["provider"] = settings.provider
    report["domains"] = settings.domains
    report["interval_seconds"] = settings.interval_seconds
    report["pinned_node"] = pin_node
    report["namespace"] = STYX_NAMESPACE

    if dry_run:
        report["manifest"] = render_duckdns_manifest(settings, node_hostname=pin_node, token=None)
        report["actions"].append(f"would apply Namespace/{STYX_NAMESPACE}, Secret/{DUCKDNS_SECRET}, Deployment/{DUCKDNS_DEPLOYMENT}")
        return report, 0

    token = token if token is not None else os.environ.get(settings.token_env)
    if not token:
        report["status"] = "ERROR"
        report["message"] = f"DuckDNS token not set — export ${settings.token_env} before `deploy dns apply`"
        return report, 1

    manifest = render_duckdns_manifest(settings, node_hostname=pin_node, token=token)
    ok, detail = _kubectl_apply_local(manifest, sudo=sudo)
    report["actions"].append(detail)
    if not ok:
        report["status"] = "ERROR"
        report["message"] = detail
        return report, 1

    report["message"] = f"DuckDNS publisher deployed to {STYX_NAMESPACE}; publishing {', '.join(settings.domains)}"
    return report, 0


def render_dns_report_text(report: dict[str, Any]) -> str:
    """Human-readable rendering of a deploy_dns report."""
    lines: list[str] = []
    status = report.get("status", "OK")
    if report.get("dry_run"):
        lines.append(f"=== deploy dns (plan) — {status} ===")
    else:
        lines.append(f"=== deploy dns (apply) — {status} ===")

    if report.get("message"):
        lines.append(report["message"])
    if report.get("provider"):
        lines.append(f"provider: {report['provider']}")
    if report.get("domains"):
        lines.append(f"domains: {', '.join(report['domains'])}")
    if report.get("pinned_node"):
        lines.append(f"pinned to node: {report['pinned_node']}")
    if report.get("interval_seconds"):
        lines.append(f"update interval: {report['interval_seconds']}s")
    for action in report.get("actions", []):
        lines.append(f"  - {action}")
    if report.get("manifest"):
        lines.append("")
        lines.append("--- manifest ---")
        lines.append(report["manifest"].rstrip())
    return "\n".join(lines) + "\n"
