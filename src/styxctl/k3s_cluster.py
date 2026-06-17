"""Multi-node k3s cluster planning and remote orchestration for MVP2."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import shutil
import subprocess
from typing import Any, Callable

from .dns_update import detect_public_ipv4, detect_public_ipv4_remote, refresh_node_duckdns
from .inventory import SystemInventory
from .gateway import k3s_join_url, k3s_gateway_listen_args, parse_gateway_ports
from .nodes import (
    ClusterNode,
    CONNECTIVITY_BOOTSTRAP,
    CONNECTIVITY_DUCKDNS,
    all_node_tls_sans,
    init_server_node,
    node_connectivity_host,
    node_hostname,
    parse_nodes,
    sort_nodes_for_install,
)

K3S_TOKEN_PATH = "/var/lib/rancher/k3s/server/node-token"

RunResult = tuple[bool, str]


@dataclass(slots=True)
class ClusterNodePlan:
    node: ClusterNode
    role: str
    target_host: str
    node_ips: list[str]
    tls_sans: list[str]
    k3s_env: dict[str, str]
    k3s_args: list[str]
    command_display: str
    status: str = "pending"
    detail: str | None = None
    local_execution: bool = False
    ssh_port: int = 47810
    resolved_ipv4: str | None = None

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["node"] = self.node.to_dict()
        return data


@dataclass(slots=True)
class ClusterPlan:
    init_node: str
    nodes: list[ClusterNodePlan] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    join_url: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "init_node": self.init_node,
            "join_url": self.join_url,
            "warnings": list(self.warnings),
            "nodes": [item.to_dict() for item in self.nodes],
        }


def _k3s_network_args(config: dict[str, Any]) -> list[str]:
    cluster = config.get("cluster", {})
    network = config.get("network", {})
    mode = cluster.get("mode", "dual-stack")
    args: list[str] = []

    if mode in {"dual-stack", "ipv4-only"}:
        pod_ipv4 = network.get("pod_ipv4")
        service_ipv4 = network.get("service_ipv4")
        if isinstance(pod_ipv4, str):
            args.extend(["--cluster-cidr", pod_ipv4])
        if isinstance(service_ipv4, str):
            args.extend(["--service-cidr", service_ipv4])

    if mode in {"dual-stack", "ipv6-only"}:
        pod_ipv6 = network.get("pod_ipv6")
        service_ipv6 = network.get("service_ipv6")
        if isinstance(pod_ipv6, str):
            args.extend(["--cluster-cidr-v6", pod_ipv6])
        if isinstance(service_ipv6, str):
            args.extend(["--service-cidr-v6", service_ipv6])
    return args


def k3s_install_spec(
    config: dict[str, Any],
    node: ClusterNode,
    *,
    all_nodes: list[ClusterNode],
    join_url: str | None = None,
    join_token: str | None = None,
) -> tuple[dict[str, str], list[str], str]:
    args = _k3s_network_args(config)
    args.extend(k3s_gateway_listen_args(config, server_role=node.role in {"init-server", "server"}))
    env: dict[str, str] = {}

    for ip in node.all_ips():
        args.extend(["--node-ip", ip])
    for san in all_node_tls_sans(all_nodes, config):
        args.extend(["--tls-san", san])

    if node.role == "init-server":
        env["INSTALL_K3S_EXEC"] = "server"
        args.append("--cluster-init")
        display = (
            "curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='server' sh -s - "
            + " ".join(args)
        )
    elif node.role == "server":
        env["INSTALL_K3S_EXEC"] = "server"
        if join_url:
            env["K3S_URL"] = join_url
        if join_token:
            env["K3S_TOKEN"] = join_token
        display = (
            f"curl -sfL https://get.k3s.io | K3S_URL={join_url or '<init-url>'} "
            f"K3S_TOKEN=<token> INSTALL_K3S_EXEC='server' sh -s - "
            + " ".join(args)
        )
    else:
        env["INSTALL_K3S_EXEC"] = "agent"
        if join_url:
            env["K3S_URL"] = join_url
        if join_token:
            env["K3S_TOKEN"] = join_token
        display = (
            f"curl -sfL https://get.k3s.io | K3S_URL={join_url or '<init-url>'} "
            f"K3S_TOKEN=<token> INSTALL_K3S_EXEC='agent' sh -s - "
            + " ".join(args)
        )
    return env, args, display


def build_cluster_plan(
    config: dict[str, Any],
    *,
    local_node: ClusterNode | None = None,
    inventory: SystemInventory | None = None,
    join_url: str | None = None,
    join_token: str | None = None,
) -> ClusterPlan:
    nodes = parse_nodes(config)
    gateway = parse_gateway_ports(config)
    init_node = init_server_node(nodes)
    if init_node is None:
        return ClusterPlan(init_node="unknown", warnings=["no init-server node defined"])

    init_host = node_connectivity_host(
        config,
        init_node,
        mode=CONNECTIVITY_BOOTSTRAP,
        inventory=inventory,
        local_node=local_node,
    )
    if join_url is None and init_host:
        join_url = k3s_join_url(init_host, gateway)

    plans: list[ClusterNodePlan] = []
    warnings: list[str] = []
    for node in sort_nodes_for_install(nodes):
        host = node_connectivity_host(
            config,
            node,
            mode=CONNECTIVITY_BOOTSTRAP,
            inventory=inventory,
            local_node=local_node,
        )
        if not host:
            warnings.append(f"node {node.name} has no public_ipv4 for bootstrap connectivity")
            continue
        resolved = node.resolved_ipv4(config, mode=CONNECTIVITY_BOOTSTRAP)
        env, args, display = k3s_install_spec(
            config,
            node,
            all_nodes=nodes,
            join_url=join_url if node.role != "init-server" else None,
            join_token=join_token if node.role != "init-server" else None,
        )
        plans.append(
            ClusterNodePlan(
                node=node,
                role=node.role,
                target_host=host,
                node_ips=node.all_ips(),
                tls_sans=all_node_tls_sans(nodes, config),
                k3s_env=env,
                k3s_args=args,
                command_display=display,
                local_execution=local_node is not None and local_node.name == node.name,
                ssh_port=gateway.ssh,
                resolved_ipv4=resolved,
            )
        )

    return ClusterPlan(init_node=init_node.name, nodes=plans, warnings=warnings, join_url=join_url)


def _ssh_target(
    node: ClusterNode,
    fallback_user: str | None,
    config: dict[str, Any],
    *,
    mode: str = CONNECTIVITY_BOOTSTRAP,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
) -> str:
    user = node.ssh_user or fallback_user
    host = (
        node_connectivity_host(
            config,
            node,
            mode=mode,
            inventory=inventory,
            local_node=local_node,
        )
        or node.name
    )
    return f"{user}@{host}" if user else host


def _run_ssh_command(
    target: str,
    remote_command: str,
    *,
    port: int = 47810,
    timeout: float = 900.0,
) -> RunResult:
    if shutil.which("ssh") is None:
        return False, "ssh command not found"
    try:
        completed = subprocess.run(
            [
                "ssh",
                "-p",
                str(port),
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                target,
                remote_command,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"ssh timed out after {timeout} seconds"
    except OSError as exc:
        return False, str(exc)

    detail = (completed.stderr or completed.stdout or "").strip()
    if completed.returncode == 0:
        return True, detail or "ok"
    return False, detail or f"ssh exit code {completed.returncode}"


def fetch_join_token_from_init(
    init_node: ClusterNode,
    *,
    config: dict[str, Any],
    ssh_user: str | None = None,
    runner: Callable[..., RunResult] | None = None,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
) -> RunResult:
    gateway = parse_gateway_ports(config)
    target = _ssh_target(init_node, ssh_user, config, inventory=inventory, local_node=local_node)
    run = runner or _run_ssh_command
    return run(target, f"sudo cat {K3S_TOKEN_PATH}", port=gateway.ssh)


def _remote_k3s_install_command(env: dict[str, str], args: list[str]) -> str:
    env_exports = " ".join(f"{key}='{value}'" for key, value in env.items())
    arg_text = " ".join(args)
    return f"curl -sfL https://get.k3s.io | {env_exports} sh -s - {arg_text}"


def apply_cluster_node_plan(
    plan: ClusterNodePlan,
    *,
    config: dict[str, Any],
    ssh_user: str | None,
    runner: Callable[..., RunResult] | None = None,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
) -> ClusterNodePlan:
    if plan.local_execution:
        plan.status = "skipped"
        plan.detail = "local node handled by install local"
        return plan

    target = _ssh_target(plan.node, ssh_user, config, inventory=inventory, local_node=local_node)
    remote_command = _remote_k3s_install_command(plan.k3s_env, plan.k3s_args)
    run = runner or _run_ssh_command
    ok, detail = run(target, remote_command, port=plan.ssh_port)
    plan.status = "installed" if ok else "failed"
    plan.detail = detail
    return plan


def _node_public_ipv4_for_duckdns(
    config: dict[str, Any],
    node: ClusterNode,
    *,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
    ssh_user: str | None = None,
    runner: Callable[..., RunResult] | None = None,
    connectivity_mode: str = CONNECTIVITY_BOOTSTRAP,
) -> str | None:
    if local_node is not None and node.name == local_node.name:
        return detect_public_ipv4()

    gateway = parse_gateway_ports(config)
    run = runner or _run_ssh_command
    target = _ssh_target(
        node,
        ssh_user,
        config,
        mode=connectivity_mode,
        inventory=inventory,
        local_node=local_node,
    )
    detected = detect_public_ipv4_remote(target, port=gateway.ssh, runner=run)
    if detected:
        return detected
    if connectivity_mode == CONNECTIVITY_DUCKDNS:
        target = _ssh_target(
            node,
            ssh_user,
            config,
            mode=CONNECTIVITY_BOOTSTRAP,
            inventory=inventory,
            local_node=local_node,
        )
        return detect_public_ipv4_remote(target, port=gateway.ssh, runner=run)
    return None


def refresh_cluster_duckdns(
    config: dict[str, Any],
    nodes: list[ClusterNode],
    *,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
    ssh_user: str | None = None,
    runner: Callable[..., RunResult] | None = None,
    connectivity_mode: str = CONNECTIVITY_BOOTSTRAP,
) -> list[str]:
    """Publish each node's current public IPv4 to DuckDNS after cluster connectivity is up."""
    messages: list[str] = []
    for node in nodes:
        public_ip = _node_public_ipv4_for_duckdns(
            config,
            node,
            inventory=inventory,
            local_node=local_node,
            ssh_user=ssh_user,
            runner=runner,
            connectivity_mode=connectivity_mode,
        )
        ok, detail = refresh_node_duckdns(config, node, ipv4=public_ip)
        host = node_hostname(config, node) or node.public_ipv4 or node.name
        if ok:
            messages.append(f"{host}: DuckDNS published ({detail})")
        else:
            messages.append(f"{host}: DuckDNS publish skipped ({detail})")
    return messages


def assess_cluster_nodes(
    config: dict[str, Any],
    *,
    inventory: SystemInventory | None = None,
    ssh_user: str | None = None,
    runner: Callable[..., RunResult] | None = None,
    local_node: ClusterNode | None = None,
    connectivity_mode: str = CONNECTIVITY_DUCKDNS,
) -> dict[str, Any]:
    nodes = parse_nodes(config)
    gateway = parse_gateway_ports(config)
    init_node = init_server_node(nodes)
    results: list[dict[str, Any]] = []
    issues: list[str] = []
    run = runner or _run_ssh_command

    kubectl_nodes: list[str] = []
    if init_node:
        target = _ssh_target(
            init_node,
            ssh_user,
            config,
            mode=connectivity_mode,
            inventory=inventory,
            local_node=local_node,
        )
        ok, detail = run(target, "sudo kubectl get nodes -o json", port=gateway.ssh)
        if ok:
            try:
                payload = json.loads(detail)
                for item in payload.get("items", []):
                    name = item.get("metadata", {}).get("name")
                    ready = any(
                        condition.get("type") == "Ready" and condition.get("status") == "True"
                        for condition in item.get("status", {}).get("conditions", [])
                    )
                    kubectl_nodes.append(name or "unknown")
                    if not ready:
                        issues.append(f"kubectl reports node {name} not Ready")
            except json.JSONDecodeError:
                issues.append("could not parse kubectl get nodes output from init server")
        else:
            issues.append(f"could not query kubectl on init server: {detail}")

    for node in nodes:
        host = node_connectivity_host(
            config,
            node,
            mode=connectivity_mode,
            inventory=inventory,
            local_node=local_node,
        ) or node.name
        target = _ssh_target(
            node,
            ssh_user,
            config,
            mode=connectivity_mode,
            inventory=inventory,
            local_node=local_node,
        )
        ok, detail = run(target, "sudo systemctl is-active k3s || sudo systemctl is-active k3s-agent", port=gateway.ssh)
        resolved = node.resolved_ipv4(config, mode=connectivity_mode)
        entry = {
            "name": node.name,
            "role": node.role,
            "hostname": node_hostname(config, node),
            "connectivity_host": host,
            "public_ipv4": node.public_ipv4,
            "ipv4": node.ipv4,
            "ipv6": node.ipv6,
            "resolved_ipv4": resolved,
            "reachable": ok,
            "k3s_active": detail.strip() == "active" if ok else False,
            "detail": detail,
        }
        results.append(entry)
        if not ok:
            issues.append(f"node {node.name} ({host}:{gateway.ssh}) is not reachable or k3s is not active")

    expected = {node.name for node in nodes}
    if kubectl_nodes and expected - set(kubectl_nodes):
        missing = ", ".join(sorted(expected - set(kubectl_nodes)))
        issues.append(f"cluster missing kubectl nodes: {missing}")

    healthy = not issues and len(results) == len(nodes) and all(item["k3s_active"] for item in results)
    init_host = (
        node_connectivity_host(
            config,
            init_node,
            mode=connectivity_mode,
            inventory=inventory,
            local_node=local_node,
        )
        if init_node
        else None
    )
    return {
        "healthy": healthy,
        "connectivity_mode": connectivity_mode,
        "init_node": init_node.name if init_node else None,
        "join_url": k3s_join_url(init_host, gateway) if init_host else None,
        "kubectl_nodes": kubectl_nodes,
        "nodes": results,
        "issues": issues,
    }


def local_node_plan_from_cluster(
    cluster_plan: ClusterPlan,
    local_node: ClusterNode,
) -> ClusterNodePlan | None:
    for item in cluster_plan.nodes:
        if item.node.name == local_node.name:
            return item
    return None
