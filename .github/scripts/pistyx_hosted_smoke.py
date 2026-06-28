#!/usr/bin/env python3
"""Hosted-runner smoke checks for the movable pistyx entrypoint.

The render checks are deterministic and do not need a live cluster. The public
probe verifies DNS/UDP routeability from a GitHub-hosted runner; a real
WireGuard handshake is handled by the workflow when CI client secrets exist.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / ".github" / "fixtures" / "styx.test.yaml"
STYXCTL = os.environ.get("STYXCTL", "styxctl")

SITE_PUBLIC_IPV4 = {
    "pegasus": "198.51.100.10",
    "atlas": "198.51.100.10",
    "hydra": "198.51.100.20",
    "kraken": "198.51.100.20",
}

SITE_HOSTNAMES = {
    "pegasus": "pipegasus.duckdns.org",
    "atlas": "piatlas.duckdns.org",
    "hydra": "pihydra.duckdns.org",
    "kraken": "pikraken.duckdns.org",
}


def run_styxctl(workdir: Path, *args: str) -> str:
    completed = subprocess.run(
        [STYXCTL, *args],
        cwd=workdir,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise AssertionError(f"styxctl {' '.join(args)} exited {completed.returncode}")
    return completed.stdout


def write_config(workdir: Path, *, current_host: str | None = None) -> None:
    config = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    for node in config["nodes"]:
        name = node["name"]
        node["hostname"] = SITE_HOSTNAMES[name]
        node["public_ipv4"] = SITE_PUBLIC_IPV4[name]
    if current_host:
        config["pistyx"] = {"current_host": current_host}
    else:
        config.pop("pistyx", None)
    (workdir / "styx.yaml").write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")


def deployment_domains(output: str) -> dict[str, set[str]]:
    marker = "--- manifest ---"
    if marker not in output:
        raise AssertionError("deploy dns plan did not include a manifest")
    manifest = output.split(marker, 1)[1]
    by_leader: dict[str, set[str]] = {}
    for doc in yaml.safe_load_all(manifest):
        if not isinstance(doc, dict) or doc.get("kind") != "Deployment":
            continue
        spec = doc["spec"]["template"]["spec"]
        leader = spec["nodeSelector"]["kubernetes.io/hostname"]
        env = spec["containers"][0]["env"]
        domains = next(item["value"] for item in env if item.get("name") == "DUCKDNS_DOMAINS")
        by_leader[leader] = set(domains.split(","))
    return by_leader


def assert_holder(workdir: Path, holder: str) -> None:
    info = run_styxctl(workdir, "mesh", "pistyx", "show")
    if f"holder {holder}" not in info:
        raise AssertionError(f"expected pistyx holder {holder!r} in pistyx info:\n{info}")

    mesh = run_styxctl(workdir, "mesh", "plan")
    if f"pistyx (egress gateway): {holder}" not in mesh:
        raise AssertionError(f"expected mesh plan to place pistyx on {holder!r}:\n{mesh}")
    if f"--- {holder} [StyxEgress] ---" not in mesh:
        raise AssertionError(f"expected {holder!r} to render the StyxEgress PoP:\n{mesh}")

    dns = run_styxctl(workdir, "deploy", "dns", "plan")
    domains = deployment_domains(dns)
    if holder not in domains:
        raise AssertionError(f"expected a DuckDNS publisher pinned to {holder!r}: {domains}")
    if "pistyx" not in domains[holder]:
        raise AssertionError(f"expected {holder!r} publisher to include pistyx: {domains}")
    wrong = {leader: names for leader, names in domains.items() if leader != holder and "pistyx" in names}
    if wrong:
        raise AssertionError(f"pistyx published by non-holder site(s): {wrong}")


def render_checks() -> None:
    with tempfile.TemporaryDirectory(prefix="styx-pistyx-smoke-") as tmp:
        workdir = Path(tmp)

        write_config(workdir)
        assert_holder(workdir, "pegasus")

        client = run_styxctl(workdir, "client", "config", "hosted-smoke", "--render-only")
        expected = [
            "Endpoint = pistyx.duckdns.org:47801",
            "Address = 10.0.250.2/32, fd00:cafe:0:250::2/128",
            "AllowedIPs = 0.0.0.0/0, ::/0",
            "PersistentKeepalive = 25",
        ]
        for needle in expected:
            if needle not in client:
                raise AssertionError(f"missing {needle!r} from client config:\n{client}")

        write_config(workdir, current_host="hydra")
        assert_holder(workdir, "hydra")

        moved_client = run_styxctl(workdir, "client", "config", "hosted-smoke", "--render-only")
        if "Endpoint = pistyx.duckdns.org:47801" not in moved_client:
            raise AssertionError("client endpoint should remain the floating pistyx name after a move")

    print("pistyx render/move checks passed")


def public_probe(host: str, port: int) -> None:
    infos = socket.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_DGRAM)
    addresses = []
    routeable = []
    failures = []
    for family, socktype, proto, _canon, sockaddr in infos:
        address = sockaddr[0]
        if address in addresses:
            continue
        addresses.append(address)
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(5)
                sock.connect(sockaddr)
            routeable.append(address)
        except OSError as exc:
            failures.append(f"{address}: {exc}")
    if not addresses:
        raise AssertionError(f"{host} did not resolve to any UDP endpoint")
    if not routeable:
        detail = "; ".join(failures) if failures else "no routeable addresses"
        raise AssertionError(f"{host}:{port}/udp resolved but no address was routeable: {detail}")
    print(f"{host}:{port}/udp resolved to {', '.join(addresses)}")
    print(f"{host}:{port}/udp routeable from this runner via {', '.join(routeable)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--render-checks", action="store_true")
    parser.add_argument("--public-probe", action="store_true")
    parser.add_argument("--host", default="pistyx.duckdns.org")
    parser.add_argument("--port", type=int, default=47801)
    args = parser.parse_args()

    if not args.render_checks and not args.public_probe:
        parser.error("choose --render-checks, --public-probe, or both")

    if args.render_checks:
        render_checks()
    if args.public_probe:
        public_probe(args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
