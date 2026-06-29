"""WireGuard endpoint re-resolution — follow DuckDNS repoints without manual reconnects.

WireGuard resolves a peer's ``Endpoint`` hostname exactly once (at config load) and then pins the
IP forever. So when a leader's or pistyx's public IP changes (a DuckDNS repoint, or pistyx moving
to a faster site), every peer dialing it by name keeps hammering the stale IP. The fix is the
canonical ``reresolve-dns`` loop: periodically re-resolve each peer's Endpoint hostname and
``wg set ... endpoint`` it if the address changed.

Node side (this module): a ``styx-reresolve`` DaemonSet — hostNetwork + privileged so ``wg set``
hits the real host interfaces, hostPath ``/etc/wireguard`` to read the ``.conf``s. It covers every
WG interface present on a node (``Styx`` everywhere, ``StyxEgress`` on leaders) and survives a mesh
partition (the local kubelet keeps it running), so it's there exactly when an endpoint goes stale.

Client side: ``styxctl client config`` emits a companion systemd ``.service`` + ``.timer`` (see
``render_client_reresolve_unit``) for Linux clients; the mobile WireGuard apps already
re-resolve on handshake failure / network change.

Deploy with ``styxctl deploy reresolve apply``; remove with ``styxctl deploy reresolve delete``.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STYX_NAMESPACE = "styx-system"
RERESOLVE_APP = "styx-reresolve"
MANAGED_BY = "styxctl"

DEFAULT_IMAGE = "alpine:3.20"
DEFAULT_INTERVAL_SECONDS = 30

RunResult = tuple[bool, str]


@dataclass(slots=True)
class ReresolveSettings:
    image: str
    interval_seconds: int


def parse_reresolve_settings(config: dict[str, Any]) -> ReresolveSettings:
    raw = config.get("reresolve")
    raw = raw if isinstance(raw, dict) else {}
    image = raw.get("image")
    image = image.strip() if isinstance(image, str) and image.strip() else DEFAULT_IMAGE
    interval = raw.get("interval_seconds", DEFAULT_INTERVAL_SECONDS)
    if not isinstance(interval, int) or interval <= 0:
        interval = DEFAULT_INTERVAL_SECONDS
    return ReresolveSettings(image=image, interval_seconds=interval)


# The re-resolve loop. Iterates every /etc/wireguard/*.conf, and for each [Peer] whose Endpoint is
# a HOSTNAME (not a literal IP), re-resolves it and `wg set`s the running endpoint if it changed.
# Skips literal v4/v6 endpoints (nothing to re-resolve) and IPv6 (bracketed) endpoints.
_RERESOLVE_SCRIPT = r"""
set -u
command -v wg >/dev/null 2>&1 && command -v dig >/dev/null 2>&1 || apk add --no-cache wireguard-tools bind-tools >/dev/null 2>&1 || true
echo "styx-reresolve: re-resolving WG endpoint hostnames every ${INTERVAL}s"
while true; do
  for conf in /host/etc/wireguard/*.conf; do
    [ -f "$conf" ] || continue
    iface="$(basename "$conf" .conf)"
    pub=""
    while IFS= read -r line; do
      key="$(printf '%s' "$line" | sed -n 's/^[[:space:]]*\([A-Za-z]*\)[[:space:]]*=.*/\1/p')"
      val="$(printf '%s' "$line" | sed -n 's/^[^=]*=[[:space:]]*\(.*\)/\1/p')"
      case "$line" in
        *"[Peer]"*) pub="" ;;
      esac
      [ "$key" = "PublicKey" ] && pub="$val"
      if [ "$key" = "Endpoint" ] && [ -n "$pub" ]; then
        host="${val%:*}"; port="${val##*:}"
        case "$host" in
          *"["*|*"::"*) continue ;;        # skip IPv6 literals
          *[a-zA-Z]*)                        # only hostnames (have letters); skip v4 literals
            new="$(dig +short "$host" A 2>/dev/null | grep -E '^[0-9.]+$' | head -n1)"
            [ -n "$new" ] || continue
            cur="$(wg show "$iface" endpoints 2>/dev/null | awk -v p="$pub" '$1==p{print $2}')"
            if [ "$cur" != "$new:$port" ]; then
              if wg set "$iface" peer "$pub" endpoint "$new:$port" 2>/dev/null; then
                echo "styx-reresolve: $iface $host -> $new:$port"
              fi
            fi ;;
        esac
      fi
    done < "$conf"
  done
  sleep "${INTERVAL}"
done
"""

_NAMESPACE = """\
apiVersion: v1
kind: Namespace
metadata:
  name: __NAMESPACE__
  labels:
    app.kubernetes.io/managed-by: __MANAGED_BY__
"""

_DAEMONSET = """\
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: __APP__
  namespace: __NAMESPACE__
  labels:
    app.kubernetes.io/name: __APP__
    app.kubernetes.io/managed-by: __MANAGED_BY__
spec:
  selector:
    matchLabels:
      app.kubernetes.io/instance: __APP__
  template:
    metadata:
      labels:
        app.kubernetes.io/name: __APP__
        app.kubernetes.io/instance: __APP__
    spec:
      hostNetwork: true
      dnsPolicy: Default
      priorityClassName: system-node-critical
      tolerations:
        - operator: Exists
      containers:
        - name: reresolve
          image: "__IMAGE__"
          securityContext:
            privileged: true
          env:
            - name: INTERVAL
              value: "__INTERVAL__"
          command: ["/bin/sh", "-c"]
          args:
            - |__SCRIPT__
          volumeMounts:
            - name: host-wg
              mountPath: /host/etc/wireguard
              readOnly: true
          resources:
            requests:
              cpu: 5m
              memory: 16Mi
            limits:
              memory: 48Mi
      volumes:
        - name: host-wg
          hostPath:
            path: /etc/wireguard
            type: DirectoryOrCreate
"""


def _fill(template: str, repl: dict[str, str]) -> str:
    for marker, value in repl.items():
        template = template.replace(marker, value)
    return template


def _indented_script() -> str:
    # Indent the script body to sit under the YAML block scalar `args: - |`.
    return "".join("\n" + (" " * 14 + line if line.strip() else "") for line in _RERESOLVE_SCRIPT.splitlines())


def render_reresolve_manifest(settings: ReresolveSettings) -> str:
    common = {"__NAMESPACE__": STYX_NAMESPACE, "__MANAGED_BY__": MANAGED_BY}
    return _fill(_NAMESPACE, common) + _fill(_DAEMONSET, {
        **common,
        "__APP__": RERESOLVE_APP,
        "__IMAGE__": settings.image,
        "__INTERVAL__": str(settings.interval_seconds),
        "__SCRIPT__": _indented_script(),
    })


def render_client_reresolve_unit(interface: str = "wg-styx") -> str:
    """A companion systemd .service + .timer a Linux client drops in to follow pistyx repoints."""
    return f"""\
# /etc/systemd/system/styx-reresolve@.service  +  styx-reresolve@.timer
# Enable on a Linux client with:  systemctl enable --now styx-reresolve@{interface}.timer
# --- styx-reresolve@.service ---
[Unit]
Description=Styx WireGuard endpoint re-resolution for %i
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'host=$(awk -F"= *" "/^Endpoint/{{e=$2}} END{{split(e,a,\\":\\"); print a[1]}}" /etc/wireguard/%i.conf); \\
  port=$(awk -F":" "/^Endpoint/{{print $NF}}" /etc/wireguard/%i.conf); \\
  pub=$(wg show %i peers); \\
  new=$(dig +short "$host" A | grep -E "^[0-9.]+$" | head -n1); \\
  [ -n "$new" ] && wg set %i peer "$pub" endpoint "$new:$port"'

# --- styx-reresolve@.timer ---
[Unit]
Description=Re-resolve Styx WireGuard endpoints periodically for %i

[Timer]
OnBootSec=30
OnUnitActiveSec=30

[Install]
WantedBy=timers.target
"""


def _kubectl(args: list[str], *, sudo: bool, stdin: str | None = None) -> RunResult:
    if shutil.which("kubectl") is None and not (sudo and shutil.which("sudo")):
        return False, "kubectl not found on PATH"
    command = (["sudo"] if sudo else []) + ["kubectl", *args]
    try:
        completed = subprocess.run(command, check=False, input=stdin, capture_output=True, text=True, timeout=120.0)
    except subprocess.TimeoutExpired:
        return False, "kubectl timed out after 120s"
    except OSError as exc:
        return False, str(exc)
    if completed.returncode == 0:
        return True, (completed.stdout or "ok").strip()
    return False, (completed.stderr or completed.stdout or "").strip() or f"kubectl exit {completed.returncode}"


def deploy_reresolve(*, dry_run: bool, config_path: str | Path | None = None, sudo: bool = True) -> tuple[dict[str, Any], int]:
    from .config import find_config, load_config, resolve_config

    report: dict[str, Any] = {"status": "OK", "dry_run": dry_run, "actions": []}
    candidate = Path(config_path) if config_path is not None else find_config()
    config = resolve_config(load_config(candidate)) if candidate else {}
    settings = parse_reresolve_settings(config)
    report["namespace"] = STYX_NAMESPACE
    report["interval_seconds"] = settings.interval_seconds
    manifest = render_reresolve_manifest(settings)

    if dry_run:
        report["manifest"] = manifest
        report["actions"].append(f"would apply Namespace/{STYX_NAMESPACE} + DaemonSet/{RERESOLVE_APP}")
        return report, 0

    ok, detail = _kubectl(["apply", "-f", "-"], sudo=sudo, stdin=manifest)
    report["actions"].append(detail)
    if not ok:
        report["status"] = "ERROR"
        report["message"] = detail
        return report, 1
    report["message"] = f"{RERESOLVE_APP} deployed to {STYX_NAMESPACE} (re-resolves every {settings.interval_seconds}s)"
    return report, 0


def uninstall_reresolve(*, sudo: bool = True) -> tuple[dict[str, Any], int]:
    report: dict[str, Any] = {"status": "OK", "deleting": True, "actions": []}
    ok, detail = _kubectl(
        ["delete", f"daemonset/{RERESOLVE_APP}", "-n", STYX_NAMESPACE, "--ignore-not-found"], sudo=sudo
    )
    report["actions"].append(f"delete {RERESOLVE_APP}: {detail}")
    if not ok:
        report["status"] = "ERROR"
        report["message"] = f"failed to delete {RERESOLVE_APP}: {detail}"
        return report, 1
    report["message"] = f"{RERESOLVE_APP} removed (WG endpoints stay at their last-resolved IPs)"
    return report, 0


def render_reresolve_report_text(report: dict[str, Any]) -> str:
    mode = "delete" if report.get("deleting") else ("plan" if report.get("dry_run") else "apply")
    lines = [f"=== deploy reresolve ({mode}) — {report.get('status', 'OK')} ==="]
    if report.get("message"):
        lines.append(report["message"])
    if report.get("interval_seconds"):
        lines.append(f"interval: {report['interval_seconds']}s")
    for action in report.get("actions", []):
        lines.append(f"  - {action}")
    if report.get("manifest"):
        lines.append("")
        lines.append(report["manifest"].rstrip())
    return "\n".join(lines) + "\n"
