"""Cluster DNS resolver + forced /etc/resolv.conf — all pod-based, with a clean uninstall.

Two DaemonSets in the styx-system namespace:

  * ``styx-resolver`` — a node-local CoreDNS cache on 127.0.0.1:53 (hostNetwork). Forcing every
    node at 127.0.0.1 can never create a chicken-and-egg, because the resolver is ALWAYS local to
    the node (it isn't a cluster Service IP that could be unreachable). CoreDNS forwards out to the
    configured upstreams; cluster-internal pods keep using kube-dns as normal.

  * ``styx-resolv-enforcer`` — a privileged DaemonSet that points each node's /etc/resolv.conf at
    127.0.0.1 and ``chattr +i`` locks it so dhcpcd / NetworkManager / systemd-resolved can't clobber
    it. It only forces DNS AFTER the local resolver answers, and a SIGTERM trap reverses everything
    (``chattr -i`` + restore the backup) — so deleting the DaemonSet cleanly un-forces every node.

Deploy with ``styxctl deploy resolver apply``; tear down with ``styxctl deploy resolver delete``
(every Styx deployment has a one-shot uninstall: delete by the managed-by label).
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STYX_NAMESPACE = "styx-system"
RESOLVER_APP = "styx-resolver"
ENFORCER_APP = "styx-resolv-enforcer"
MANAGED_BY = "styxctl"

DEFAULT_COREDNS_IMAGE = "coredns/coredns:1.11.1"
DEFAULT_ENFORCER_IMAGE = "alpine:3.20"
DEFAULT_UPSTREAMS = ("1.1.1.1", "9.9.9.9")

RunResult = tuple[bool, str]


@dataclass(slots=True)
class ResolverSettings:
    coredns_image: str
    enforcer_image: str
    upstreams: list[str]
    force: bool          # whether to deploy the resolv.conf enforcer (the immutable lock)


def parse_resolver_settings(config: dict[str, Any]) -> ResolverSettings:
    """Read the optional ``resolver:`` block; everything has a sensible default."""
    raw = config.get("resolver")
    raw = raw if isinstance(raw, dict) else {}

    coredns_image = raw.get("coredns_image")
    coredns_image = coredns_image.strip() if isinstance(coredns_image, str) and coredns_image.strip() else DEFAULT_COREDNS_IMAGE

    enforcer_image = raw.get("enforcer_image")
    enforcer_image = enforcer_image.strip() if isinstance(enforcer_image, str) and enforcer_image.strip() else DEFAULT_ENFORCER_IMAGE

    upstreams_raw = raw.get("upstreams")
    upstreams = [str(u).strip() for u in upstreams_raw if str(u).strip()] if isinstance(upstreams_raw, list) else []
    if not upstreams:
        upstreams = list(DEFAULT_UPSTREAMS)

    force = raw.get("force", True)
    force = bool(force) if isinstance(force, bool) else True

    return ResolverSettings(
        coredns_image=coredns_image,
        enforcer_image=enforcer_image,
        upstreams=upstreams,
        force=force,
    )


# --------------------------------------------------------------------------- manifests

_NAMESPACE = """\
apiVersion: v1
kind: Namespace
metadata:
  name: __NAMESPACE__
  labels:
    app.kubernetes.io/managed-by: __MANAGED_BY__
"""

_COREFILE_CONFIGMAP = """\
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: styx-resolver-corefile
  namespace: __NAMESPACE__
  labels:
    app.kubernetes.io/name: __RESOLVER_APP__
    app.kubernetes.io/managed-by: __MANAGED_BY__
data:
  Corefile: |
    .:53 {
        bind 127.0.0.1 ::1
        cache 30
        forward . __UPSTREAMS__ {
            policy sequential
        }
        loop
        errors
        reload
    }
"""

# Node-local CoreDNS cache on 127.0.0.1:53 (hostNetwork). Always local to the node, so forcing
# resolv.conf -> 127.0.0.1 can never strand a node on an unreachable resolver.
_RESOLVER_DAEMONSET = """\
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: __RESOLVER_APP__
  namespace: __NAMESPACE__
  labels:
    app.kubernetes.io/name: __RESOLVER_APP__
    app.kubernetes.io/managed-by: __MANAGED_BY__
spec:
  selector:
    matchLabels:
      app.kubernetes.io/instance: __RESOLVER_APP__
  template:
    metadata:
      labels:
        app.kubernetes.io/name: __RESOLVER_APP__
        app.kubernetes.io/instance: __RESOLVER_APP__
    spec:
      hostNetwork: true
      dnsPolicy: Default
      priorityClassName: system-node-critical
      tolerations:
        - operator: Exists
      containers:
        - name: coredns
          image: "__COREDNS_IMAGE__"
          args: ["-conf", "/etc/coredns/Corefile"]
          securityContext:
            capabilities:
              add: ["NET_BIND_SERVICE"]
          volumeMounts:
            - name: corefile
              mountPath: /etc/coredns
              readOnly: true
          resources:
            requests:
              cpu: 25m
              memory: 32Mi
            limits:
              memory: 128Mi
      volumes:
        - name: corefile
          configMap:
            name: styx-resolver-corefile
"""

# Privileged enforcer: point /etc/resolv.conf at the node-local resolver and chattr +i lock it.
# Forces DNS only AFTER 127.0.0.1:53 answers, and a TERM trap reverses everything on teardown.
_ENFORCER_DAEMONSET = r"""---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: __ENFORCER_APP__
  namespace: __NAMESPACE__
  labels:
    app.kubernetes.io/name: __ENFORCER_APP__
    app.kubernetes.io/managed-by: __MANAGED_BY__
spec:
  selector:
    matchLabels:
      app.kubernetes.io/instance: __ENFORCER_APP__
  template:
    metadata:
      labels:
        app.kubernetes.io/name: __ENFORCER_APP__
        app.kubernetes.io/instance: __ENFORCER_APP__
    spec:
      hostNetwork: true
      dnsPolicy: Default
      priorityClassName: system-node-critical
      terminationGracePeriodSeconds: 30
      tolerations:
        - operator: Exists
      containers:
        - name: enforcer
          image: "__ENFORCER_IMAGE__"
          securityContext:
            privileged: true
          command: ["/bin/sh", "-c"]
          args:
            - |
              set -eu
              RC=/host/etc/resolv.conf
              BK=/host/etc/resolv.conf.styx-backup
              command -v chattr >/dev/null 2>&1 || apk add --no-cache e2fsprogs-extra >/dev/null 2>&1 || true
              restore() {
                chattr -i "$RC" 2>/dev/null || true
                if [ -f "$BK" ]; then cp "$BK" "$RC" && rm -f "$BK"; fi
                echo "styx-resolv-enforcer: restored $RC"
                exit 0
              }
              trap restore TERM INT
              # Force DNS only once the node-local resolver is actually answering.
              i=0
              while [ "$i" -lt 60 ]; do
                if nslookup -type=ns . 127.0.0.1 >/dev/null 2>&1 || nc -z -w1 127.0.0.1 53 2>/dev/null; then break; fi
                i=$((i + 1)); sleep 1
              done
              [ -f "$BK" ] || cp "$RC" "$BK"
              chattr -i "$RC" 2>/dev/null || true
              printf 'nameserver 127.0.0.1\noptions edns0 trust-ad\n' > "$RC"
              chattr +i "$RC" 2>/dev/null || true
              echo "styx-resolv-enforcer: forced $RC -> 127.0.0.1 (immutable)"
              while true; do sleep 3600 & wait $!; done
          volumeMounts:
            - name: host-etc
              mountPath: /host/etc
          resources:
            requests:
              cpu: 5m
              memory: 8Mi
            limits:
              memory: 32Mi
      volumes:
        - name: host-etc
          hostPath:
            path: /etc
            type: Directory
"""


def _fill(template: str, repl: dict[str, str]) -> str:
    for marker, value in repl.items():
        template = template.replace(marker, value)
    return template


def render_resolver_manifest(settings: ResolverSettings) -> str:
    """Render Namespace + Corefile ConfigMap + resolver DaemonSet (+ enforcer DaemonSet if force)."""
    common = {"__NAMESPACE__": STYX_NAMESPACE, "__MANAGED_BY__": MANAGED_BY}
    parts = [
        _fill(_NAMESPACE, common),
        _fill(_COREFILE_CONFIGMAP, {**common, "__RESOLVER_APP__": RESOLVER_APP, "__UPSTREAMS__": " ".join(settings.upstreams)}),
        _fill(_RESOLVER_DAEMONSET, {**common, "__RESOLVER_APP__": RESOLVER_APP, "__COREDNS_IMAGE__": settings.coredns_image}),
    ]
    if settings.force:
        parts.append(_fill(_ENFORCER_DAEMONSET, {**common, "__ENFORCER_APP__": ENFORCER_APP, "__ENFORCER_IMAGE__": settings.enforcer_image}))
    return "".join(parts)


def _kubectl(args: list[str], *, sudo: bool, stdin: str | None = None) -> RunResult:
    if shutil.which("kubectl") is None and not (sudo and shutil.which("sudo")):
        return False, "kubectl not found on PATH"
    command = (["sudo"] if sudo else []) + ["kubectl", *args]
    try:
        completed = subprocess.run(
            command, check=False, input=stdin, capture_output=True, text=True, timeout=120.0
        )
    except subprocess.TimeoutExpired:
        return False, "kubectl timed out after 120s"
    except OSError as exc:
        return False, str(exc)
    if completed.returncode == 0:
        return True, (completed.stdout or "ok").strip()
    return False, (completed.stderr or completed.stdout or "").strip() or f"kubectl exit {completed.returncode}"


def deploy_resolver(*, dry_run: bool, config_path: str | Path | None = None, sudo: bool = True) -> tuple[dict[str, Any], int]:
    """Render (and, unless dry_run, apply) the node-local resolver + the resolv.conf enforcer."""
    from .config import find_config, load_config, resolve_config

    report: dict[str, Any] = {"status": "OK", "dry_run": dry_run, "actions": []}
    candidate = Path(config_path) if config_path is not None else find_config()
    config = resolve_config(load_config(candidate)) if candidate else {}
    settings = parse_resolver_settings(config)

    report["namespace"] = STYX_NAMESPACE
    report["upstreams"] = settings.upstreams
    report["force"] = settings.force
    manifest = render_resolver_manifest(settings)

    if dry_run:
        report["manifest"] = manifest
        components = f"DaemonSet/{RESOLVER_APP}" + (f" + DaemonSet/{ENFORCER_APP} (immutable resolv.conf)" if settings.force else "")
        report["actions"].append(f"would apply Namespace/{STYX_NAMESPACE}, Corefile ConfigMap, {components}")
        return report, 0

    ok, detail = _kubectl(["apply", "-f", "-"], sudo=sudo, stdin=manifest)
    report["actions"].append(detail)
    if not ok:
        report["status"] = "ERROR"
        report["message"] = detail
        return report, 1
    report["message"] = f"node-local resolver{' + resolv.conf enforcer' if settings.force else ''} deployed to {STYX_NAMESPACE}"
    return report, 0


def uninstall_resolver(*, sudo: bool = True) -> tuple[dict[str, Any], int]:
    """One-shot uninstall: delete the resolver + enforcer by label. The enforcer's TERM trap
    restores each node's /etc/resolv.conf as its pod terminates, so DNS un-forces cleanly."""
    report: dict[str, Any] = {"status": "OK", "actions": []}
    # Delete the enforcer FIRST and wait, so every node un-chattrs + restores resolv.conf before
    # the resolver it points at goes away.
    for kind, app in ((f"daemonset/{ENFORCER_APP}", ENFORCER_APP), (f"daemonset/{RESOLVER_APP}", RESOLVER_APP)):
        ok, detail = _kubectl(
            ["delete", kind, "-n", STYX_NAMESPACE, "--ignore-not-found", "--wait=true", "--timeout=60s"],
            sudo=sudo,
        )
        report["actions"].append(f"delete {app}: {detail}")
        if not ok:
            report["status"] = "ERROR"
            report["message"] = f"failed to delete {app}: {detail}"
            return report, 1
    ok, detail = _kubectl(
        ["delete", "configmap/styx-resolver-corefile", "-n", STYX_NAMESPACE, "--ignore-not-found"],
        sudo=sudo,
    )
    report["actions"].append(f"delete corefile: {detail}")
    report["message"] = "resolver + enforcer removed; nodes restored to their original resolv.conf"
    return report, 0


def render_resolver_report_text(report: dict[str, Any]) -> str:
    mode = "plan" if report.get("dry_run") else ("delete" if report.get("deleting") else "apply")
    lines = [f"=== deploy resolver ({mode}) — {report.get('status', 'OK')} ==="]
    if report.get("message"):
        lines.append(report["message"])
    if report.get("upstreams"):
        lines.append(f"upstreams: {', '.join(report['upstreams'])}")
    if "force" in report:
        lines.append(f"force resolv.conf (immutable): {'yes' if report['force'] else 'no'}")
    for action in report.get("actions", []):
        lines.append(f"  - {action}")
    if report.get("manifest"):
        lines.append("")
        lines.append(report["manifest"].rstrip())
    return "\n".join(lines) + "\n"
