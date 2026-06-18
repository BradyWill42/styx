# styxctl

**The control CLI for [Styx](https://github.com/BradyWill42/styx)** — a k3s-native, dual-stack WireGuard mesh and access gateway platform.

`styxctl` prepares Linux gateway nodes, installs the k3s foundation, and (in future milestones) deploys the full Styx mesh. The CLI is **command-discovery-first**: composable subcommands, no workflow flags, and shell tab completion.

| | |
|---|---|
| **Version** | `0.3.0` |
| **Python** | 3.10+ |
| **License** | MIT |
| **Status** | MVP1 + MVP2 shipped on `main` |

---

## Table of contents

- [What is Styx?](#what-is-styx)
- [Architecture](#architecture)
- [Repository branches](#repository-branches)
- [Quick start](#quick-start)
- [Milestone roadmap](#milestone-roadmap)
- [MVP1: Assess and remediate](#mvp1-assess-and-remediate)
- [MVP2: Install prerequisites](#mvp2-install-prerequisites)
- [Configuration (`styx.yaml`)](#configuration-styxyaml)
- [Reserved port plan](#reserved-port-plan)
- [Safety doctrine](#safety-doctrine)
- [Command reference](#command-reference)
- [Reports and artifacts](#reports-and-artifacts)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Continuous integration](#continuous-integration)
- [License](#license)

---

## What is Styx?

Styx is a homelab and small-site platform that combines:

- **k3s** for lightweight Kubernetes orchestration across gateway nodes
- **Dual-stack WireGuard** (`Styx` interface on UDP `47800`) for mesh connectivity — separate from any existing `wg0` tunnel you already run
- **Reserved service ports** (`47800–47850`) for gateway APIs, agents, diagnostics, and metrics
- **Declarative cluster config** in `styx.yaml` — nodes, CIDRs, DNS endpoints, and future SIEM integration

`styxctl` is the operator-facing tool that drives each phase. It collects inventory, remediates only what is provably safe, installs k3s with your network plan, and writes human-readable plus machine-readable reports at every step.

---

## Architecture

```mermaid
flowchart TB
    subgraph operator["Operator workstation"]
        CLI["styxctl CLI"]
        CFG["styx.yaml"]
        RPT["reports/styx/"]
    end

    subgraph mvp1["MVP1 — Sysprep"]
        INV["Inventory collection"]
        PORTS["Port scan 47800–47850"]
        SAFE["Safe remediation"]
    end

    subgraph mvp2["MVP2 — Install"]
        K3S["k3s cluster"]
        WG["WireGuard Styx interface"]
        SSH["SSH cluster join"]
    end

    subgraph future["MVP3+ — Deploy"]
        DEPLOY["Gateway workloads"]
        CLIENT["Client profiles"]
        SIEM["Wazuh SIEM"]
    end

    CLI --> CFG
    CLI --> INV --> PORTS
    PORTS --> SAFE
    SAFE --> K3S
    K3S --> WG
    K3S --> SSH
    WG --> DEPLOY
    CLI --> RPT
    DEPLOY --> CLIENT
    DEPLOY --> SIEM
```

**Node roles** (defined in `styx.yaml`):

| Role | Purpose |
|------|---------|
| `init-server` | Bootstraps the k3s cluster with `--cluster-init` and dual-stack CIDRs |
| `server` | Additional k3s control-plane / server node |
| `agent` | k3s worker node |

Each node uses `public_ipv4` (router WAN IP with port forwards) for bootstrap SSH and k3s joins, `hostname` (DuckDNS) for stable naming after the cluster is connected, and mesh `ipv4` / `ipv6` for k3s `--node-ip`. Install and cluster join start on gateway ports `47810` (SSH) and `47811` (k3s API) over each node's public IP; DuckDNS is published only after networking, LAN leader election, and node joins succeed. After cutover, cluster status and doctor checks use DuckDNS hostnames and can refresh stale records.

---

## Repository branches

| Branch | Contents | Use when |
|--------|----------|----------|
| [`main`](https://github.com/BradyWill42/styx/tree/main) | MVP1 + MVP2 integrated release with `public_ipv4` bootstrap, DuckDNS post-cluster publish, gateway ports, and LAN leader election | Default — full platform prep and install |
| [`MVP1`](https://github.com/BradyWill42/styx/tree/MVP1) | MVP1-only sysprep snapshot | You only need assessment and safe remediation |
| [`MVP2`](https://github.com/BradyWill42/styx/tree/MVP2) | MVP1 + install path with `public_ipv4` bootstrap, DuckDNS post-cluster publish, gateway ports, and LAN leader election | Milestone development on the install path |

All branches share the same CLI design, safety rules, and **this README**. `main` combines MVP1 and MVP2; `MVP1` and `MVP2` are preserved milestone snapshots for targeted work.

Current branch notes:

- Documentation audit `2026-06-18 00:00 UTC`: fetched all remote heads. `main`, `MVP1`, and `MVP2` were still at `35f0697` from the 23:00 README audit; active cursor branches added DuckDNS steady-state connectivity refresh (`cursor/duckdns-cutover-connectivity-0281` at `b67401c`) and CI branch-trigger cleanup (`cursor/remove-mvp-branches-0281` at `ae45126`). This README-only update records the audit and documents the DuckDNS refresh surface.
- Bootstrap connectivity uses each node's `public_ipv4` and router 1:1 port forwards (`47810` SSH, `47811` k3s API).
- DuckDNS (`hostname`) is published only after local networking, LAN leader election, and cluster join succeed.
- `cluster.leader: lan-elected` elects the strongest configured peer on the local LAN (UDP `47802`), ignoring peers not listed in `styx.yaml`.

---

## Quick start

### 1. Install `styxctl`

```bash
git clone https://github.com/BradyWill42/styx.git
cd styx

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Verify:

```bash
styxctl version
styxctl --help
```

### 2. Prepare a gateway node (MVP1)

```bash
styxctl sysprep check local
styxctl sysprep safe plan local      # preview only
styxctl sysprep safe apply local     # apply without prompt
styxctl sysprep check local          # re-check until READY
```

### 3. Install the foundation (MVP2)

```bash
cp styx.yaml.example styx.yaml
# Set each node's public_ipv4 (router WAN), DuckDNS hostname, and mesh ipv4/ipv6
# Export DUCKDNS_TOKEN for post-cluster DNS publish
export DUCKDNS_TOKEN=your-token
styxctl config validate

styxctl install plan local
styxctl install apply local          # on every node

styxctl install plan cluster
styxctl install apply cluster        # bootstrap over public_ipv4 + gateway ports

styxctl install status local
styxctl install status cluster
styxctl install doctor local
styxctl install doctor cluster
styxctl dns refresh cluster           # refresh DuckDNS records after ISP IP changes
```

### Requirements

| Requirement | MVP1 | MVP2 |
|-------------|------|------|
| Linux gateway host | Yes | Yes |
| Python 3.10+ (for CLI) | Yes | Yes |
| `sudo` (non-interactive for mutating commands) | Recommended | Required |
| `ss` / `iproute2` | Recommended | Installed by MVP2 |
| Passwordless SSH to configured nodes | No | Required for `install cluster` |
| `styx.yaml` | Optional | Required |

---

## Milestone roadmap

| Milestone | Status | Scope |
|-----------|--------|-------|
| **MVP1** | Shipped | Read-only inventory, port scan, safe remediation |
| **MVP2** | Shipped | k3s install, `Styx` WireGuard interface, multi-node cluster join |
| **MVP3** | Planned | `sysprep reset` / `nuke`, `deploy`, `gateway`, `status`, `doctor` |
| **MVP4** | Planned | Remote sysprep (`check all` / `check node`), `client`, `siem` |

Placeholder commands exist today and print a clear "not implemented" message — they never mutate the host.

---

## MVP1: Assess and remediate

MVP1 answers one question: **is this node safe to install Styx on?**

### Typical workflow

```bash
styxctl sysprep check local
styxctl sysprep safe plan local
styxctl sysprep safe apply local
styxctl sysprep check local
```

1. **Check** — read-only inventory and port scan
2. **Plan** — preview safe cleanup actions (no changes)
3. **Apply** — execute safe cleanup (or use `sysprep safe local` for interactive confirm)
4. **Re-check** — repeat until `READY` or `READY_WITH_WARNINGS`

### What `sysprep check local` collects

- Host identity, OS, kernel, architecture, boot time
- Network interfaces, default route, DNS resolvers, LAN IPs
- WireGuard interfaces (including `wg0` preservation status)
- Processes and systemd units listening on ports `47800–47850`
- k3s / flannel / CNI artifacts and leftover services
- Sudo availability, time sync, disk and memory snapshot
- Detected binaries (`k3s`, `kubectl`, `wg`, `ss`, etc.)

### Readiness status

| Status | Meaning | Exit code |
|--------|---------|-----------|
| `READY` | Clear to proceed to MVP2 | `0` |
| `READY_WITH_WARNINGS` | Usable; review warnings first | `0` |
| `BLOCKED` | Critical ports `47800–47808` occupied | `1` |

When blocked, try `styxctl sysprep safe plan local` to preview cleanup, or `styxctl ports check local` to inspect conflicts.

### Safe remediation scope

**Will act on** (only when marked `safe_to_stop`):

- Styx / k3s / flannel / CNI processes in the reserved port range
- Known leftover services: `k3s.service`, `k3s-agent.service`
- Temporary Styx files under `/tmp/styx*` and `/var/tmp/styx*`

**Will never touch**:

- `wg0` or its configuration
- LAN networking, SSH, BIND, Caddy, MooseFS, home directories
- Unsafe port conflicts (non-Styx/k3s processes)
- k3s data directories (reserved for MVP3 `reset` / `nuke`)

### Port commands

```bash
styxctl ports check local          # conflicts in 47800–47850
styxctl ports list local           # full port plan
styxctl ports clear plan local     # preview safe port cleanup
styxctl ports clear apply local    # apply safe port cleanup
styxctl ports clear local          # interactive confirm
```

---

## MVP2: Install prerequisites

After MVP1 reports `READY` or `READY_WITH_WARNINGS`, MVP2 installs the local foundation on each node and optionally joins a multi-node k3s cluster.

### Typical workflow

```bash
cp styx.yaml.example styx.yaml
# Set each node's public_ipv4 (router WAN), DuckDNS hostname, and mesh ipv4/ipv6
# Export DUCKDNS_TOKEN for post-cluster DNS publish
export DUCKDNS_TOKEN=your-token
styxctl config validate

# Per-node local install (run on every gateway)
styxctl install plan local
styxctl install apply local

# Cluster join over each node's public_ipv4 (router port forwards to 47810/47811)
styxctl install plan cluster
styxctl install apply cluster

# Verify
styxctl install status local
styxctl install status cluster
styxctl install doctor local
styxctl install doctor cluster
```

Each node uses:

- `public_ipv4` — router WAN IP with 1:1 port forwards to this Pi (`47810` SSH, `47811` k3s API) for bootstrap connectivity
- `hostname` — DuckDNS name published **after** the cluster is connected
- `ipv4` / `ipv6` — mesh addresses passed to k3s as `--node-ip` (internal overlay, not your LAN or public IP)

Bootstrap order: local networking install -> LAN leader election (if enabled) -> cluster join over `public_ipv4` -> DuckDNS publish -> steady-state checks over DuckDNS hostnames.

### LAN leader election

When multiple Styx gateways share a LAN, enable automatic leader election in `styx.yaml`:

```yaml
cluster:
  leader: lan-elected
  lan_election:
    port: 47802
    collect_sec: 3
```

Before `install plan local`, `install apply local`, and `install apply cluster`, styxctl:

1. Broadcasts on the local subnet (UDP port `47802`, Styx director API)
2. Collects peer announcements from other Styx nodes on the same LAN
3. Keeps only peers listed in `styx.yaml` `nodes`
4. Scores each remaining peer by RAM, CPU cores, architecture, disk, and existing k3s
5. Elects the strongest configured peer on this LAN as leader

If the configured `init-server` is on the same LAN and two or more peers are present, the elected leader is promoted to `init-server` and the previous init-server is demoted to `server`. If the init-server lives on a different site, election still picks a LAN leader for visibility but k3s roles stay unchanged.

Preview or inspect election without installing:

```bash
styxctl install plan lan
styxctl install status lan
```

### Port forwards (router)

Forward the Styx reserved range on each gateway node's router to that node:

| External (WAN) | Forward to node | Service |
|---|---|---|
| `47800/udp` | `47800/udp` | Styx WireGuard |
| `47810/tcp` | `47810/tcp` | SSH (sshd listens on Pi) |
| `47811/tcp` | `47811/tcp` | k3s API (k3s listens on Pi) |

`install apply local` configures sshd and k3s to listen on `gateway.ssh_port` and `gateway.k3s_api_port` on the Pi itself. Router forwards are 1:1 — same port outside and inside. styxctl connects to `public_ipv4:47810` for SSH and `https://public_ipv4:47811` for k3s join during bootstrap. After the cluster is healthy, `install apply cluster` publishes each node's current public IP to DuckDNS (`hostname`).

### What MVP2 installs

| Component | Detail |
|-----------|--------|
| **Packages** | `iproute2`, WireGuard tools, `curl`, `ca-certificates` via supported `apt`, `dnf`, or `yum` hosts |
| **k3s** | Server or agent role per `styx.yaml`; dual-stack pod/service CIDRs |
| **WireGuard** | `Styx` interface on UDP `47800` (never `wg0`) |
| **Firewall** | Minimal allowance for Styx WireGuard UDP when `ufw`, `firewalld`, or `nftables` is detected |
| **Preservation** | `wg0` config hash/mtime snapshotted before and verified after |

### Install gates

Install is **blocked** when:

- `styx.yaml` is missing or `INVALID`
- Sysprep status is `BLOCKED` on ports `47800–47808`
- Non-interactive `sudo` is unavailable for mutating install steps
- Cluster join cannot reach remote nodes over SSH

Always run `install plan` before `install apply`. Interactive commands (`install local`, `install cluster`) ask for confirmation; `install apply` variants skip the prompt.

### Cluster install order

1. `init-server` node — `curl -sfL https://get.k3s.io` with `--cluster-init` and network CIDRs
2. `server` nodes — join with token from init-server
3. `agent` nodes — join as k3s agents

Remote steps use each node's `ssh_user` when set, otherwise `cluster.ssh_user` (default in example: `ubuntu`). styxctl connects to each node's `public_ipv4` on `gateway.ssh_port` (`47810` by default) and joins k3s at `https://<public_ipv4>:47811`. Ensure key-based SSH works from the machine running `styxctl` to every configured `public_ipv4`. After the cluster is healthy, DuckDNS hostnames are published. You can also set `cluster.join_token` when a non-init node must join without fetching the token from the init-server over SSH.

### Health checks

`install doctor local` exits `0` when healthy enough for MVP3 deploy work. It verifies:

- k3s installed and active
- `kubectl` available
- `Styx` WireGuard interface up
- UDP `47800` listening
- `wg0` preserved unchanged
- Critical ports clear

`install doctor cluster` checks reachability and k3s status for every configured node.

---

## Configuration (`styx.yaml`)

Copy the example and edit for your lab:

```bash
cp styx.yaml.example styx.yaml
styxctl config show
styxctl config validate
```

### Key sections

```yaml
cluster:
  name: styx
  domain: styx.net
  mode: dual-stack          # dual-stack | ipv4-only | ipv6-only
  ssh_user: ubuntu          # default SSH user for cluster join
  leader: lan-elected
  lan_election:
    port: 47802
    collect_sec: 3

gateway:
  ssh_port: 47810
  k3s_api_port: 47811

network:
  ipv4_supernet: 10.0.0.0/14
  ipv6_supernet: fd00:cafe::/48

  mesh_ipv4: 10.0.0.0/16    # Styx WireGuard address space
  infra_ipv4: 10.1.0.0/16
  pod_ipv4: 10.2.0.0/16     # k3s pods
  service_ipv4: 10.3.0.0/16

  mesh_ipv6: fd00:cafe:0::/48
  infra_ipv6: fd00:cafe:1::/56
  pod_ipv6: fd00:cafe:2::/56
  service_ipv6: fd00:cafe:3::/112

  roadwarrior_ipv4: 10.0.250.0/24
  roadwarrior_ipv6: fd00:cafe:0:250::/64

wireguard:
  interface: Styx           # must NOT be wg0
  port: 47800
  shared_server_identity: true

nodes:
  - name: node-init
    hostname: styx-lab-init.duckdns.org   # replace with your DuckDNS subdomain
    public_ipv4: 203.0.113.10           # router WAN IP with 1:1 port forwards
    ipv4: 10.0.0.1                        # mesh address for k3s --node-ip
    ipv6: fd00:cafe::1
    role: init-server
  - name: node-server
    hostname: styx-lab-server.duckdns.org
    public_ipv4: 203.0.113.11
    ipv4: 10.0.0.2
    ipv6: fd00:cafe::2
    role: server
  - name: node-agent
    hostname: styx-lab-agent.duckdns.org
    public_ipv4: 203.0.113.12
    ipv4: 10.0.0.3
    ipv6: fd00:cafe::3
    role: agent

dns:
  provider: duckdns
  domain: duckdns.org
  token_env: DUCKDNS_TOKEN
  auto_endpoint: node-init
  fixed_endpoints:
    node-server: styx-lab-server
    node-agent: styx-lab-agent

siem:
  enabled: true
  provider: wazuh           # MVP4 placeholder
  namespace: wazuh
  profile: small-lab
```

**Important:** `public_ipv4` is each node's router WAN address with port forwards to `47810`/`47811` — used for bootstrap SSH and k3s joins. `hostname` is published to DuckDNS **after** the cluster is connected. Mesh `ipv4` / `ipv6` values are k3s `--node-ip` addresses and Styx WireGuard overlay space, not LAN or public IPs.

Config validation status:

| Status | Meaning |
|--------|---------|
| `VALID` | Ready for MVP2 |
| `VALID_WITH_WARNINGS` | Usable; e.g. no nodes defined yet |
| `INVALID` | Blocking errors; fix before install |

---

## Reserved port plan

Only ports `47800–47850` are managed by `styxctl`. Critical production ports `47800–47808` block MVP2 install when occupied.

| Port | Protocol | Purpose |
|------|----------|---------|
| 47800 | UDP | Styx production WireGuard gateway |
| 47801 | TCP | Styx gateway health API |
| 47802 | UDP | Styx director API / configured-node LAN leader election |
| 47803 | TCP | Styx status dashboard/API |
| 47804 | TCP | Styx node agent API |
| 47805 | TCP | Styx Ansible controller API |
| 47806 | TCP | Styx watchdog agent API |
| 47807 | TCP | Styx local diagnostics API |
| 47808 | TCP | Styx metrics exporter |
| 47809 | any | Reserved |
| 47810 | TCP | SSH gateway listen |
| 47811 | TCP | k3s API gateway listen |
| 47812–47819 | any | Site/gateway spare |
| 47820–47829 | any | Client/profile testing |
| 47830–47839 | any | Development/debug |
| 47840–47850 | any | Reserved future |

Planned WireGuard endpoint for production clients:

```ini
Endpoint = styx-lab-init.duckdns.org:47800
```

---

## Safety doctrine

Styx is designed for gateway nodes that may already run critical services. `styxctl` enforces strict boundaries:

| Command class | Mutates host? | Scope |
|---------------|---------------|-------|
| `sysprep check`, `ports check`, `ports list`, `config show`, `install plan`, `install status`, `install doctor`, `report`, `version`, `completion` | No | Read-only host inspection |
| `sysprep safe`, `ports clear`, `install apply` | Yes | Only pre-identified safe targets |
| `sysprep reset`, `sysprep nuke`, `deploy` | MVP3 | Not implemented yet |

**`wg0` is sacred.** It is inventoried, reported, and hash-verified — never removed or modified by MVP1 or MVP2.

Read-only planning and reporting commands may write local artifacts under `reports/styx/`; they do not mutate gateway services or networking.

Every mutating command follows **plan → confirm → apply**:

```bash
styxctl sysprep safe plan local     # dry-run
styxctl sysprep safe local          # preview + confirm
styxctl sysprep safe apply local    # apply without confirm
```

---

## Command reference

Discover commands with tab completion:

```bash
styxctl <TAB>
styxctl sysprep <TAB>
styxctl install <TAB>
```

### Sysprep

| Command | Description |
|---------|-------------|
| `sysprep check local` | Read-only MVP1 assessment |
| `sysprep check all` | MVP4 placeholder |
| `sysprep check node` | MVP4 placeholder |
| `sysprep safe plan local` | Preview safe cleanup |
| `sysprep safe apply local` | Apply safe cleanup (no prompt) |
| `sysprep safe local` | Preview + interactive confirm |
| `sysprep reset local` | MVP3 placeholder |
| `sysprep nuke local` | MVP3 placeholder |

### Ports

| Command | Description |
|---------|-------------|
| `ports check local` | Show conflicts in reserved range |
| `ports list local` | Show full port plan |
| `ports clear plan local` | Preview safe port cleanup |
| `ports clear apply local` | Apply safe port cleanup |
| `ports clear local` | Interactive port cleanup |

### Install

| Command | Description |
|---------|-------------|
| `install plan local` | Preview local install steps |
| `install plan cluster` | Preview cluster join steps |
| `install plan lan` | Preview LAN leader election |
| `install local` | Local install with confirm |
| `install apply local` | Local install without confirm |
| `install cluster` | Cluster install with confirm |
| `install apply cluster` | Cluster install without confirm |
| `install status local` | k3s + WireGuard status table |
| `install status cluster` | All nodes reachability table |
| `install status lan` | Show LAN peers and elected leader |
| `install doctor local` | Actionable local health diagnosis |
| `install doctor cluster` | Cluster-wide health diagnosis |

### DNS

| Command | Description |
|---------|-------------|
| `dns refresh local` | Publish this node's current public IPv4 to its DuckDNS hostname |
| `dns refresh cluster` | Refresh DuckDNS for every configured node using SSH-detected public IPv4s |

### Config, sysprep reports, and shell

| Command | Description |
|---------|-------------|
| `config show` | Summarize active `styx.yaml` |
| `config validate` | Validate config; exit `1` if invalid |
| `report show [hostname]` | Display latest sysprep report |
| `report json [hostname]` | Print sysprep report as JSON |
| `version` | Print `styxctl` version |
| `completion bash\|zsh\|fish` | Print shell completion script |
| `--install-completion` | Install completion for active shell |

### Future (placeholders)

```bash
styxctl deploy soon      # MVP3
styxctl gateway soon     # MVP3
styxctl status soon      # MVP3
styxctl doctor soon      # MVP3
styxctl client soon      # MVP4
styxctl siem soon        # MVP4
```

---

## Reports and artifacts

### Sysprep reports (MVP1)

```text
./reports/styx/<hostname>/sysprep-report.json
./reports/styx/<hostname>/sysprep-report.txt
```

### Install reports (MVP2)

```text
./reports/styx/<hostname>/install-report.json
./reports/styx/<hostname>/install-report.txt
```

Inspect saved sysprep reports:

```bash
styxctl report show
styxctl report json
```

Sysprep reports include timestamps, readiness status, warnings, blocking reasons, inventory snapshots, and planned/applied action outcomes. Install plan/apply commands also save `install-report.*` artifacts in the same host report directory; the `report` subcommands currently read the sysprep report bundle.

---

## Troubleshooting

### `BLOCKED` after sysprep check

```bash
styxctl ports check local
styxctl sysprep safe plan local
styxctl sysprep safe apply local
styxctl sysprep check local
```

If a non-Styx process holds a critical port, stop it manually — MVP1 will not kill unsafe processes.

### Install blocked: invalid config

```bash
styxctl config validate
```

Common fixes: set node `hostname` to the correct DuckDNS name, mesh IPs for k3s `--node-ip`, ensure exactly one `init-server`, port-forward `47810`/`47811`, and keep `wireguard.interface` as `Styx` (not `wg0`).

### Install blocked: sudo unavailable

Ensure passwordless sudo for the installing user, or run from an account that has it:

```bash
sudo -n true && echo "sudo ok" || echo "sudo required"
```

### k3s not active after install

```bash
sudo systemctl status k3s
styxctl install doctor local
styxctl install apply local
```

### Cluster join failures

```bash
# From init-server, verify SSH to each node hostname on gateway port 47810
ssh -p 47810 ubuntu@<node-hostname> true

styxctl install status cluster
styxctl install doctor cluster
```

Ensure every node has completed `install apply local` before `install apply cluster`.

### `wg0` preservation warning

Investigate any changes to `/etc/wireguard/wg0.conf` before retrying. MVP2 snapshots `wg0` before install and compares afterward.

---

## Development

### Setup

```bash
python -m pip install -e ".[dev]"
```

### Run tests

```bash
python -m pytest -v
```

### Manual smoke checks

```bash
styxctl sysprep check local
styxctl sysprep safe plan local
styxctl config validate
styxctl install plan local
styxctl report show
```

### Project layout

```text
src/styxctl/
  cli.py              # Typer entry point and command tree
  inventory.py        # Read-only host inventory (MVP1)
  ports.py            # Reserved port scan and plan
  remediation.py      # Safe cleanup actions (MVP1)
  reports.py          # Sysprep report generation
  config.py           # styx.yaml load and validate
  nodes.py            # Cluster node parsing
  install.py          # Local + cluster install (MVP2)
  k3s_cluster.py      # k3s cluster planning and SSH orchestration
  install_report.py   # Install report generation
tests/                # pytest suite
styx.yaml.example     # Reference cluster configuration
```

---

## Continuous integration

Every pull request to `main`, `MVP1`, or `MVP2` runs CI. Pushes to those branches and automation branches also run CI:

1. **Test matrix** — Python 3.10, 3.11, 3.12: pytest, CLI smoke, wheel build
2. **Sysprep/install smoke** — read-only `sysprep`, `ports`, `config`, and `install plan/status/doctor` checks on a GitHub-hosted Ubuntu runner; uploads report artifacts

View results in the repository **Actions** tab. Download the **sysprep-report-github-hosted** artifact to inspect JSON and text reports from CI.

CI validates the full check and plan path on real Linux, but it is **not** a substitute for running MVP1 on your own gateway hardware.

---

## License

MIT — see [LICENSE](LICENSE).

Copyright (c) 2026 Brady Williams
