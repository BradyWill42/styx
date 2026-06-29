from styxctl.inventory import SystemInventory
from styxctl.ports import PortScanResult
from styxctl.uninstall import build_uninstall_plan


def _inventory(*, interfaces: list[str], wg_interfaces: list[str]) -> SystemInventory:
    return SystemInventory(
        generated_at="2026-06-29T00:00:00+00:00",
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
        interface_names=interfaces,
        wireguard_interfaces=wg_interfaces,
        ports=PortScanResult(
            range_start=47800,
            range_end=47850,
            scanner="test",
            command_available=False,
            returncode=None,
            timed_out=False,
            error=None,
            stdout="",
            stderr="",
            conflicts=[],
        ),
        detected_binaries={},
        detected_services={},
        detected_artifacts={},
        cni_interfaces=[],
        firewall_backend={},
        commands={},
    )


def test_uninstall_targets_site_and_egress_wireguard_interfaces(tmp_path):
    config = tmp_path / "styx.yaml"
    config.write_text(
        """
cluster:
  name: styx
wireguard:
  interface: Styx
  port: 47800
egress:
  interface: StyxEgress
""".lstrip(),
        encoding="utf-8",
    )
    inventory = _inventory(
        interfaces=["Styx", "StyxSite1", "StyxEgress", "wg0"],
        wg_interfaces=["Styx", "StyxSite1", "StyxEgress", "wg0"],
    )

    plan = build_uninstall_plan(config_path=config, inventory=inventory)
    by_name = {step.name: step for step in plan.steps}

    assert by_name["wg-down"].reason == "Styx interface is currently up"
    assert by_name["wg-down:StyxSite1"].status == "pending"
    assert by_name["wg-down:StyxEgress"].status == "pending"
    assert not any(step.name.endswith(":wg0") for step in plan.steps)
