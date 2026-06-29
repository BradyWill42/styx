# Styx — Handoff / Onboarding

`styxctl` is a **k3s-native, dual-stack WireGuard mesh gateway platform** for Raspberry Pi
fleets spread across multiple **sites** (places with distinct public IPs; multiple nodes behind
one public IP are one site). It preps nodes
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
- **Per-site Pi overlays** (`StyxSite<N>`) — every Pi renders one site WG config per physical WAN site, preserving the Pi's `.10+` host suffix across all `10.0.N.0/24` site scopes. The site entrypoint routes the other Pi identities for that site.

## 2. Designed but deferred (the rest of the overlay)

The **backbone** mesh and per-site Pi overlays are built. Still **designed, not built**:
`styx`-as-movable-hub, leader-to-styx uplinks beyond the current routed site entrypoints, the
`pistyx` quickest-site loop, and automated client registration. These are only meaningfully
testable once **pithor** is a real *remote* second site.

## 3. Roadmap (ordered)

1. **Dispatch `styx-cluster-e2e`** (with `DUCKDNS_TOKEN` set) → confirm the per-site publisher pods schedule onto the leaders and actually update DuckDNS. *This is the only unproven runtime bit.*
2. **Bring pithor online as a real remote 2nd site** → unblocks all cross-site mesh work.
3. **Movable styx hub / richer site routing** (backbone + per-site Pi overlays are done): leader-to-styx uplinks beyond the current routed entrypoints, NAT-aware policy, and styx-as-movable-hub.
4. **`pistyx` quickest-site loop** — client lands on current `pistyx` site → that site asks peers over styx if one is quicker (probe the client's WAN IP; fallback hop-count or client-side probe) → repoint `pistyx` → client reconnects.
5. **Client automation** — roadwarrior config rendering exists; automatic registration and fastest-site selection are still deferred.
6. **Remaining MVP3:** `gateway`, `sysprep reset` / `nuke`.

## 4. Architecture (two-tier overlay)

- **Styx backbone WG `10.0.0.0/24` (+ IPv6)** — every k3s Pi is a member; this is the cluster network. The styx *server* role is movable between sites by client speed (the dynamic part).
- **Per-site ranges** — each site (a distinct public-IP place) has its own v4/v6 range. Every Pi gets the backbone `Styx` config plus one `StyxSite<N>` config per site. Site *k* = `10.0.k.0/24`; pistyx is `.1`, clients are `.2+`, and Pi identities use a stable reserved `.10+` suffix across all sites.
- **Leaders** — each site LAN-elects or selects an entrypoint (`lan_election.py`, `site_entrypoint`, init-server, then first node). It's the port-forward face + DuckDNS publisher + routed site overlay entrypoint. **NAT**: only the port-forwarded leader/entrypoint is reachable cross-site; regular Pis route site traffic via that entrypoint. (Same reason SSH uses ProxyJump.)
- **Clients** — roadwarriors are mobile site members. The site index changes the third octet (`10.0.<site>.0/24`), while the last octet is the stable device identity, so `10.0.1.7` and `10.0.2.7` are the same client in two site scopes. The conventional mobile site is `10.0.250.0/24`.
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

- `src/styxctl/`: `cli.py`, `config.py`, `nodes.py`, `network_plan.py` (IP plan), `network_detect.py` (DuckDNS resolve + LAN scan), `bootstrap_config.py` (config enrichment), `k3s_cluster.py` (install/connect, SSH + ProxyJump), `install.py`, `dns_publish.py` (per-site publishers), `cluster_status.py` (status/doctor), `wireguard_mesh.py` (backbone + per-site WG overlays), `lan_election.py`.
- `.github/workflows/`: `styx-runners.yml` (primary), `ci.yml`, `styx-cluster-e2e.yml` (manual), `runner-smoke.yml`.
- `.github/scripts/`: `generate_styx_config.py` (labels→styx.yaml), `runner_lib.py`, `stage1-prerequisites.py`, `stage2-connectivity.py`.
- `styx.yaml.example`: cluster settings + reference nodes (CI regenerates the `nodes:` from labels; the listed nodes are a real-deploy reference only).

## 9. Known issues / cleanup

- **Runtime verification:** per-push CI can render and sanity-check; live k3s behavior still requires the manual `Styx cluster E2E` workflow.
- **Deferred overlay work:** leader-to-styx uplinks beyond the current routed entrypoints, movable `styx` hub behavior, and the `pistyx` quickest-site loop are still planned.

## 10. Gotchas / hard-won lessons

- **No local Python on the dev machine** → CI is the only verifier. Per-push CI can't run a cluster; runtime behavior (install, `deploy dns apply`, `status`/`doctor`) is **e2e-only**.
- **DuckDNS has no GeoDNS / per-client routing** — "fastest site" must be client-measured, or a server-side single-record repoint (the `pistyx` loop).
- **NAT** — cross-site, only the port-forwarded leader/entrypoint is reachable; non-leaders go via ProxyJump (SSH) or route through the leader (WG).
- **Name-collision footgun** — never derive `{node}.duckdns.org` from bare node names (`atlas`/`pegasus` resolve to *strangers'* boxes). Always set an explicit, unique `hostname:` (e.g. `pipegasus.duckdns.org`).
