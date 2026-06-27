# Styx — Handoff / Onboarding

`styxctl` is a **k3s-native, dual-stack WireGuard mesh gateway platform** for Raspberry Pi
fleets spread across multiple **sites** (LANs behind separate public IPs). It preps nodes
(sysprep), installs the k3s + WireGuard foundation, and is growing a cross-site mesh.
Command-discovery-first Typer CLI. Status as of **2026-06-26**: MVP1 + MVP2 shipped; MVP3 in progress.

---

## 1. What's built & CI-verified

- **DuckDNS discovery** — peers are found by resolving each node's DuckDNS `hostname` (no ssh-by-bare-name, which never worked cross-site). styxctl only *reads* DNS, so no token needed for discovery.
- **Label-driven CI** — the runner-integration workflow lists online runners via the GitHub API, gates on roles, **generates `styx.yaml` from the runner labels** (single source of truth), and runs a **dynamic per-machine matrix** (one job per online runner).
- **Single-init-server enforcement** — exactly one runner may carry the `init-server` label (enforced in the discover gate *and* `validate_nodes`).
- **Per-site DuckDNS publishers** (`styxctl deploy dns`) — one updater Deployment **per site, pinned to that site's leader**, publishing the site's DuckDNS names (derived from node `hostname`s) → the site's **public IPv4+IPv6** (dual-stack). The token is a Secret from `$DUCKDNS_TOKEN`, never in `styx.yaml`.
- **`styxctl status` / `styxctl doctor`** — cluster node health + the per-site publishers, with remediation hints.
- **Styx backbone WG mesh** (`styxctl mesh plan` / `mesh up`) — **hub-and-spoke**: the init-server is the WG hub; every other k3s node is a spoke that routes the whole supernet (`10.0.0.0/14` + `fd00:cafe::/48`) through it (`PersistentKeepalive=25`). Each node keeps its own private key; `mesh up` (on the init-server) collects only *public* keys over SSH, then has each node render its own `[Peer]` blocks (`mesh apply-local`). The render is **CI-verified** (`mesh plan`); `mesh up` runtime is **E2E-only** (no live cluster per-push). See `wireguard_mesh.py`.

## 2. Designed but deferred (the rest of the overlay)

The **backbone** mesh above is built. Still **designed, not built**: the per-site `/24` carve (`assign_node_mesh_ips` is still FLAT), the second per-site WG net (intra-site full mesh), `styx`-as-movable-hub, the `pistyx` quickest-site loop, and the MVP4 `client` tool. These are only meaningfully testable once **pithor** is a real *remote* second site.

## 3. Roadmap (ordered)

1. **Dispatch `styx-cluster-e2e`** (with `DUCKDNS_TOKEN` set) → confirm the per-site publisher pods schedule onto the leaders and actually update DuckDNS. *This is the only unproven runtime bit.*
2. **Bring pithor online as a real remote 2nd site** → unblocks all cross-site mesh work.
3. **Per-site WG nets** (backbone hub-and-spoke is done): per-site `/24` carve in `network_plan.assign_node_mesh_ips` (leader `.1`, site 0 = styx); the *second* WG net per node (intra-site full mesh + leader↔styx uplinks, NAT-aware); styx-as-movable-hub.
4. **`pistyx` quickest-site loop** — client lands on current `pistyx` site → that site asks peers over styx if one is quicker (probe the client's WAN IP; fallback hop-count or client-side probe) → repoint `pistyx` → client reconnects.
5. **MVP4 `client` tool** — roadwarrior clients dial a specific site or `pistyx`, homed to the site they enter.
6. **Remaining MVP3:** `gateway`, `sysprep reset` / `nuke`.

## 4. Architecture (two-tier overlay)

- **Styx backbone WG `10.0.0.0/24` (+ IPv6)** — every k3s Pi is a member; this is the cluster network. The styx *server* role is movable between sites by client speed (the dynamic part).
- **Per-site ranges** — each site (a LAN) has its own v4/v6 range; a Pi is on **two** WG nets (styx backbone + its site). Intended carve: site *k* = `10.0.k.0/24`, **leader at `.1`**, **site 0 = styx** (the connector). *(Currently `assign_node_mesh_ips` is FLAT — the carve isn't built.)*
- **Leaders** — each site LAN-elects a leader (`lan_election.py`); it's the port-forward face + DuckDNS publisher + styx uplink. **NAT**: only the port-forwarded leader is reachable cross-site, so inter-site peering is leader↔styx; regular Pis route via their leader. (Same reason SSH uses ProxyJump.)
- **Clients** (`roadwarrior 10.0.250.0/24`) — connect to **edge sites**, homed to the site they enter; never to styx (`10.0.0.0`) directly.
- **Exactly one init-server total** (k3s `--cluster-init` bootstrapper, at the styx site). `server` (HA) optional, ~one per site. "Site leader" is an *overlay* role, orthogonal to k3s init-server/server/agent.

## 5. CI / verification

- **`Styx runner integration`** (self-hosted, the primary gate): `discover` (online runners via `RUNNER_API_TOKEN` → gate: exactly 1 init-server + ≥1 agent online → generate `styx.yaml` from labels → per-machine matrix) → `uninstall` → `stage 1` (prereqs + gateway SSH on 47810) → `stage 2` (SSH connectivity) → `summary`.
- **`CI`** (GitHub-hosted): package sanity — `styxctl --help`, `deploy dns plan` render, `status/doctor --help`, wheel build.
- **`Styx cluster E2E`** (manual, destructive): full install + `mesh up` + `deploy dns` + `status` + `doctor` against a live cluster. **The only workflow that exercises runtime cluster behavior** (per-push CI has no live k3s).
- **Verify a run** with `gh run view <id> --json conclusion` — do **not** trust a watch-wrapper exit code (a trailing `echo` masks `gh run watch`'s real status — this bit us once).

## 6. Secrets (repo → Settings → Actions secrets)

| Secret | Purpose | Notes |
|---|---|---|
| `PIPASS` | sshpass password for SSH on 47810 (stage 2) | shared Pi login password |
| `DUCKDNS_TOKEN` | DuckDNS record updates (`deploy dns`) | fine to be one account token |
| `RUNNER_API_TOKEN` | discover job lists runners | **fine-grained PAT, `Administration: read`** — `GITHUB_TOKEN` can't list runners (403) |

## 7. Runner labels (source of truth)

Each runner carries `self-hosted, Linux, ARM64`, **its own name** (so `runs-on` can pin per-machine), and a **role** label. Current intent: `pegasus`=init-server, `hydra`+`atlas`=agent, `kraken`=server, `thor`=server (remote, offline). Exactly one init-server. Re-label a runner → next CI run regenerates `styx.yaml` automatically.

## 8. Key files

- `src/styxctl/`: `cli.py`, `config.py`, `nodes.py`, `network_plan.py` (IP plan), `network_detect.py` (DuckDNS resolve + LAN scan), `bootstrap_config.py` (config enrichment), `k3s_cluster.py` (install/connect, SSH + ProxyJump), `install.py`, `dns_publish.py` (per-site publishers), `cluster_status.py` (status/doctor), `wireguard_mesh.py` (backbone hub-and-spoke mesh), `lan_election.py`.
- `.github/workflows/`: `styx-runners.yml` (primary), `ci.yml`, `styx-cluster-e2e.yml` (manual), `runner-smoke.yml`.
- `.github/scripts/`: `generate_styx_config.py` (labels→styx.yaml), `runner_lib.py`, `stage1-prerequisites.py`, `stage2-connectivity.py`.
- `styx.yaml.example`: cluster settings + reference nodes (CI regenerates the `nodes:` from labels; the listed nodes are a real-deploy reference only).

## 9. Known issues / cleanup

- **Bug (unfixed):** `lan_election.parse_root_avail_kb` guards `len(parts) >= 4` but indexes `parts[5]` — a 1-line fix.
- **Doc staleness:** the README "Continuous integration" section predates the label-driven matrix (still describes fixed role legs / "all three runners pegasus, kraken, thor").
- **Minor:** `node_connectivity_host` carries vestigial `mode`/`config` indirection (works; could simplify).

## 10. Gotchas / hard-won lessons

- **No local Python on the dev machine** → CI is the only verifier. Per-push CI can't run a cluster; runtime behavior (install, `deploy dns apply`, `status`/`doctor`) is **e2e-only**.
- **DuckDNS has no GeoDNS / per-client routing** — "fastest site" must be client-measured, or a server-side single-record repoint (the `pistyx` loop).
- **NAT** — cross-site, only the port-forwarded leader/entrypoint is reachable; non-leaders go via ProxyJump (SSH) or route through the leader (WG).
- **Name-collision footgun** — never derive `{node}.duckdns.org` from bare node names (`atlas`/`pegasus` resolve to *strangers'* boxes). Always set an explicit, unique `hostname:` (e.g. `pipegasus.duckdns.org`).
