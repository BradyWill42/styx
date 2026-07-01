"""Port remap: gateway SSH -> 47800/tcp (with WireGuard 47800/udp), k3s API -> 47801/tcp
(with pistyx egress 47801/udp). Pure tests — no cluster, no SSH."""

from styxctl.config import DEFAULT_CONFIG
from styxctl.gateway import (
    DEFAULT_K3S_API_PORT,
    DEFAULT_SSH_PORT,
    GatewayPorts,
    k3s_join_url,
    parse_gateway_ports,
)
from styxctl.inventory import SystemInventory
from styxctl.ports import (
    PORT_PLAN,
    PortConflict,
    PortScanResult,
    planned_protocol,
    planned_protocols,
    port_purpose,
    port_purpose_for,
    styx_planned_listeners,
)
from styxctl.reports import CRITICAL_PORTS, evaluate_readiness


# --------------------------------------------------------------------------- gateway defaults

def test_gateway_defaults_moved_to_47800_and_47801():
    assert DEFAULT_SSH_PORT == 47800
    assert DEFAULT_K3S_API_PORT == 47801
    ports = GatewayPorts()
    assert (ports.ssh, ports.k3s_api) == (47800, 47801)
    # ssh != k3s_api and ssh != 22, so validation still passes after the move.
    assert ports.validate() == []


def test_parse_gateway_ports_defaults_and_config_symbolic():
    assert parse_gateway_ports({}).ssh == 47800
    assert parse_gateway_ports({}).k3s_api == 47801
    # DEFAULT_CONFIG references the gateway.py constants, so it tracks the move automatically.
    assert DEFAULT_CONFIG["gateway"]["ssh_port"] == 47800
    assert DEFAULT_CONFIG["gateway"]["k3s_api_port"] == 47801


def test_k3s_join_url_uses_new_api_port():
    assert k3s_join_url("pipegasus.duckdns.org", GatewayPorts()) == "https://pipegasus.duckdns.org:47801"


def test_ssh_port_may_equal_wireguard_port_different_protocol():
    # The whole point of the move: SSH (tcp) shares 47800 with WireGuard (udp). Nothing rejects it.
    assert GatewayPorts(ssh=47800, k3s_api=47801).validate() == []
    # And ssh must still differ from k3s_api (both tcp) and from admin port 22.
    assert GatewayPorts(ssh=47801, k3s_api=47801).validate()  # non-empty: same tcp port
    assert GatewayPorts(ssh=22, k3s_api=47801).validate()      # non-empty: admin SSH port


# --------------------------------------------------------------------------- port model

def test_47800_hosts_wireguard_udp_and_ssh_tcp():
    protos = planned_protocols(47800)
    assert "udp" in protos and "tcp" in protos
    assert planned_protocol(47800) == "udp+tcp"
    assert "WireGuard" in port_purpose_for(47800, "udp")
    assert "SSH" in port_purpose_for(47800, "tcp")
    assert " + " in port_purpose(47800)  # aggregate joins both


def test_47801_hosts_egress_udp_and_k3s_tcp():
    assert set(planned_protocols(47801)) == {"udp", "tcp"}
    assert "egress" in port_purpose_for(47801, "udp").lower()
    assert "k3s" in port_purpose_for(47801, "tcp").lower()


def test_old_ports_freed_and_health_api_relocated():
    # 47810/47811 are no longer the live SSH/k3s ports; both are now reserved/freed.
    assert "SSH gateway listen" not in port_purpose(47810)  # 47810 is no longer the gateway SSH port
    assert "reserved" in port_purpose(47811).lower()        # 47811 is freed, not the active k3s API
    # The live k3s API is on 47801/tcp, and it's not the old health-API reservation.
    assert "k3s" in port_purpose_for(47801, "tcp").lower()
    assert "health" not in port_purpose_for(47801, "tcp").lower()


def test_styx_planned_listeners_cover_both_protocols_on_shared_ports():
    listeners = styx_planned_listeners()
    assert {(47800, "udp"), (47800, "tcp"), (47801, "udp"), (47801, "tcp")} <= listeners


# --------------------------------------------------------------------------- readiness gate

def _conflict(port: int, protocol: str, name: str = "foreign") -> PortConflict:
    return PortConflict(
        protocol=protocol,
        port=port,
        process_name=name,
        pid=1234,
        systemd_unit=None,
        command_line=None,
        safe_to_stop=False,
        raw=f"{protocol} {port}",
    )


def _inventory_with(conflicts: list[PortConflict]) -> SystemInventory:
    return SystemInventory(
        generated_at="2026-07-01T00:00:00+00:00",
        hostname="pegasus",
        fqdn="pegasus.local",
        os_version="test",
        architecture="arm64",
        kernel_version="test",
        boot_time=None,
        current_user="runner",
        sudo_available=True,
        primary_lan_ip="192.168.1.10",
        bootstrap_ipv4="203.0.113.10",
        bootstrap_ipv6=None,
        default_route="default via 192.168.1.1",
        dns_resolvers=[],
        time_sync_status="ok",
        disk_usage="",
        memory_swap="",
        mounted_filesystems="",
        network_interfaces=[],
        interface_names=[],
        wireguard_interfaces=[],
        ports=PortScanResult(
            range_start=47800,
            range_end=47850,
            scanner="test",
            command_available=True,
            returncode=0,
            timed_out=False,
            error=None,
            stdout="",
            stderr="",
            conflicts=conflicts,
        ),
        detected_binaries={},
        detected_services={},
        detected_artifacts={},
        cni_interfaces=[],
        firewall_backend={},
        commands={},
    )


def test_readiness_does_not_block_on_styx_own_tcp_listeners_in_critical_band():
    # gateway SSH on 47800/tcp and k3s API on 47801/tcp are Styx's own — expected on a re-run.
    status, _warnings, blocking = evaluate_readiness(
        _inventory_with([_conflict(47800, "tcp", "sshd"), _conflict(47801, "tcp", "k3s")])
    )
    assert blocking == []
    assert status != "BLOCKED"


def test_readiness_still_blocks_a_foreign_squatter_on_a_critical_port():
    # 47802 is planned udp-only, so a tcp squatter there is NOT a Styx listener → blocks.
    assert (47802, "tcp") not in styx_planned_listeners()
    assert 47802 in CRITICAL_PORTS
    status, _warnings, blocking = evaluate_readiness(_inventory_with([_conflict(47802, "tcp")]))
    assert blocking
    assert status == "BLOCKED"
