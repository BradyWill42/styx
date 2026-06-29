"""Fastest-site selection brain for the movable pistyx egress (pure RTT math).

A client lands on whichever site ``pistyx.duckdns.org`` currently points at. To send its
traffic out the *closest* site, each site's leader RTT-probes the client's public IP over the
Styx backbone; the lowest-latency site should hold pistyx. This module is the decision brain and
is intentionally dependency-free so it is fully unit-testable:

  * ``parse_ping_rtt``      - pull the average RTT (ms) out of ``ping`` output.
  * ``rank_sites_by_rtt``   - order reachable sites fastest-first.
  * ``select_fastest_site`` - pick the holder, with hysteresis so a marginal win never flaps the
    DuckDNS record (which would churn every client's handshake).
  * ``rank_sites_by_consensus`` / ``select_consensus_site`` - choose one holder for the active
    client set when several clients are connected at once.

The *live* probe (SSH to each leader + ping) and the *repoint* (set ``pistyx.current_host`` ->
``styxctl mesh up`` -> ``styxctl deploy dns apply``) live in :mod:`wireguard_mesh`; they are only
meaningful with >=2 real sites online (pithor), so they are exercised e2e, not in per-push CI.
The styx-reresolve DaemonSet + the client systemd timer make peers follow the repoint without a
manual reconnect.
"""

from __future__ import annotations

import re

# Don't move pistyx unless a rival site beats the current one by more than this many ms.
# A bare margin would let measurement noise flap the floating DuckDNS record continuously.
DEFAULT_HYSTERESIS_MS = 15.0


def parse_ping_rtt(ping_output: str | None) -> float | None:
    """Return the average RTT in ms from ``ping`` output, or None if unreachable/unparseable.

    Handles Linux iputils (``rtt min/avg/max/mdev = 0.1/0.2/0.3/0.0 ms``) and BusyBox
    (``round-trip min/avg/max = 0.1/0.2/0.3 ms``) - both expose ``min/AVG/max`` after ``=``.
    """
    if not isinstance(ping_output, str):
        return None
    match = re.search(r"=\s*[\d.]+/([\d.]+)/", ping_output)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def rank_sites_by_rtt(samples: dict[int, float | None] | None) -> list[tuple[int, float]]:
    """``{site_index: rtt_ms|None}`` -> ``[(site, rtt), ...]`` fastest-first; unreachable dropped.

    Ties break on the lower site index for a stable, deterministic ordering.
    """
    reachable: list[tuple[int, float]] = []
    for site, rtt in (samples or {}).items():
        if isinstance(rtt, bool) or not isinstance(rtt, (int, float)):
            continue
        if rtt < 0:
            continue
        try:
            reachable.append((int(site), float(rtt)))
        except (TypeError, ValueError):
            continue
    return sorted(reachable, key=lambda pair: (pair[1], pair[0]))


def select_fastest_site(
    samples: dict[int, float | None] | None,
    *,
    current_site: int | None = None,
    hysteresis_ms: float = DEFAULT_HYSTERESIS_MS,
) -> int | None:
    """The site that should hold pistyx, or None if no site is reachable.

    Sticks with ``current_site`` unless another site is faster by more than ``hysteresis_ms``;
    moves immediately if the current site has gone unreachable.
    """
    ranked = rank_sites_by_rtt(samples)
    if not ranked:
        return None
    best_site, best_rtt = ranked[0]
    if current_site is None:
        return best_site
    current_rtt = next((rtt for site, rtt in ranked if site == current_site), None)
    if current_rtt is None:
        return best_site  # current holder's site is unreachable, so move off it
    if (current_rtt - best_rtt) > hysteresis_ms:
        return best_site
    return current_site


def rank_sites_by_consensus(
    client_samples: dict[str, dict[int, float | None]] | None,
) -> list[dict[str, float | int]]:
    """Rank sites for a set of active clients.

    ``client_samples`` is ``{client_name: {site_index: rtt_ms|None}}``. A single floating
    ``pistyx`` name can only point to one site, so for multiple active clients we favor sites
    that can reach the most clients, then lowest average RTT, then lower site index.
    """
    totals: dict[int, dict[str, float | int]] = {}
    for samples in (client_samples or {}).values():
        for site, rtt in rank_sites_by_rtt(samples):
            row = totals.setdefault(site, {"site": site, "reachable": 0, "total_rtt_ms": 0.0})
            row["reachable"] = int(row["reachable"]) + 1
            row["total_rtt_ms"] = float(row["total_rtt_ms"]) + rtt

    ranked: list[dict[str, float | int]] = []
    for site, row in totals.items():
        reachable = int(row["reachable"])
        if reachable <= 0:
            continue
        average = float(row["total_rtt_ms"]) / reachable
        ranked.append({"site": site, "reachable": reachable, "avg_rtt_ms": average})
    return sorted(ranked, key=lambda row: (-int(row["reachable"]), float(row["avg_rtt_ms"]), int(row["site"])))


def select_consensus_site(
    client_samples: dict[str, dict[int, float | None]] | None,
    *,
    current_site: int | None = None,
    hysteresis_ms: float = DEFAULT_HYSTERESIS_MS,
) -> int | None:
    """Choose the one site that should hold the floating ``pistyx`` name for active clients."""
    ranked = rank_sites_by_consensus(client_samples)
    if not ranked:
        return None
    best = ranked[0]
    best_site = int(best["site"])
    if current_site is None:
        return best_site

    current = next((row for row in ranked if int(row["site"]) == current_site), None)
    if current is None:
        return best_site
    best_reachable = int(best["reachable"])
    current_reachable = int(current["reachable"])
    if best_reachable > current_reachable:
        return best_site
    if best_reachable < current_reachable:
        return current_site
    if (float(current["avg_rtt_ms"]) - float(best["avg_rtt_ms"])) > hysteresis_ms:
        return best_site
    return current_site
