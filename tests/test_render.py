"""Pure WireGuard render tests — config text generation, no cluster/SSH/pithor."""

from styxctl.wireguard_mesh import (
    MeshMember,
    SiteMember,
    _site_index_for_node,
    mesh_plan,
    pistyx_clients,
    render_client_config,
    render_local_config,
    render_mesh_report_text,
    render_pistyx_pop,
    render_site_config,
)
from styxctl.nodes import parse_nodes


def test_pistyx_pop_is_a_server_not_a_default_route():
    out = render_pistyx_pop(
        "<priv>",
        [{"name": "laptop", "public_key": "PUBKEY", "ipv4": "10.0.1.2", "ipv6": None}],
        listen_port=47801,
        mtu=1420,
        gateway_v4="10.0.1.1",
        gateway_v6="fd00:cafe:0:1::1",
        stack_mode="dual-stack",
    )
    assert "Address = 10.0.1.1/24" in out            # owns the holder site's client band
    assert "ListenPort = 47801" in out
    assert "MTU = 1420" in out
    assert "PublicKey = PUBKEY" in out
    assert "AllowedIPs = 10.0.1.2/32" in out           # routed by the client's /32
    # The PoP must NEVER carry a default route — that was the severing bug.
    assert "0.0.0.0/0" not in out


def test_pistyx_pop_with_no_clients_has_no_peers():
    out = render_pistyx_pop(
        "<priv>", [], listen_port=47801, mtu=1420,
        gateway_v4="10.0.1.1", gateway_v6="fd00:cafe:0:1::1",
    )
    assert "[Interface]" in out
    assert "[Peer]" not in out


def test_client_config_full_tunnels_to_pistyx():
    out = render_client_config(
        "laptop", "<priv>",
        pistyx_pubkey="PISTYXPUB", endpoint="pistyx.duckdns.org", port=47801,
        address_v4="10.0.1.2", address_v6="fd00:cafe:0:1::2", mtu=1420,
    )
    assert "Endpoint = pistyx.duckdns.org:47801" in out
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in out
    assert "PublicKey = PISTYXPUB" in out
    assert "PersistentKeepalive = 25" in out


def test_client_config_ipv4_only_prunes_v6():
    out = render_client_config(
        "laptop", "<priv>", pistyx_pubkey="P", endpoint="pistyx.duckdns.org", port=47801,
        address_v4="10.0.1.2", address_v6=None, mtu=1420,
    )
    assert "0.0.0.0/0" in out
    assert "::/0" not in out


def test_mesh_spoke_routes_supernet_to_hub():
    members = [
        MeshMember(name="pegasus", role="init-server", ipv4="10.0.0.1", ipv6=None,
                   public_key="HUB", endpoint="pipegasus.duckdns.org"),
        MeshMember(name="hydra", role="agent", ipv4="10.0.0.2", ipv6=None, public_key="SPOKE"),
    ]
    out = render_local_config(
        "hydra", "<priv>", members, "pegasus",
        listen_port=47800, route_v4="10.0.0.0/14", route_v6="fd00:cafe::/48",
    )
    assert "AllowedIPs = 10.0.0.0/14" in out
    assert "Endpoint = pipegasus.duckdns.org:47800" in out
    assert "PersistentKeepalive = 25" in out


def test_mesh_hub_has_per_spoke_peer_not_default_route():
    members = [
        MeshMember(name="pegasus", role="init-server", ipv4="10.0.0.1", ipv6=None, public_key="HUB"),
        MeshMember(name="hydra", role="agent", ipv4="10.0.0.2", ipv6=None, public_key="SPOKE"),
    ]
    out = render_local_config(
        "pegasus", "<priv>", members, "pegasus",
        listen_port=47800, route_v4="10.0.0.0/14", route_v6="fd00:cafe::/48",
    )
    assert "AllowedIPs = 10.0.0.2/32" in out   # routed by the spoke's /32
    assert "PublicKey = SPOKE" in out


def test_site_entrypoint_routes_pi_site_identities():
    members = [
        SiteMember(
            name="pegasus", role="init-server", site_index=1, host_suffix=10,
            ipv4="10.0.1.10", ipv6=None, public_key="PEGASUS",
        ),
        SiteMember(
            name="hydra", role="server", site_index=1, host_suffix=11,
            ipv4="10.0.1.11", ipv6=None, public_key="HYDRA",
        ),
    ]
    out = render_site_config(
        "pegasus", "<priv>", members, "pegasus",
        listen_port=47821, network_v4="10.0.1.0/24", network_v6=None, stack_mode="ipv4-only",
    )
    assert "Address = 10.0.1.10/24" in out
    assert "ListenPort = 47821" in out
    assert "PublicKey = HYDRA" in out
    assert "AllowedIPs = 10.0.1.11/32" in out


def test_site_remote_pi_routes_site_scope_to_entrypoint():
    members = [
        SiteMember(
            name="pegasus", role="init-server", site_index=1, host_suffix=10,
            ipv4="10.0.1.10", ipv6=None, public_key="PEGASUS", endpoint="pipegasus.duckdns.org",
        ),
        SiteMember(
            name="hydra", role="server", site_index=1, host_suffix=11,
            ipv4="10.0.1.11", ipv6=None, public_key="HYDRA",
        ),
    ]
    out = render_site_config(
        "hydra", "<priv>", members, "pegasus",
        listen_port=47821, network_v4="10.0.1.0/24", network_v6=None, stack_mode="ipv4-only",
    )
    assert "Address = 10.0.1.11/24" in out
    assert "Endpoint = pipegasus.duckdns.org:47821" in out
    assert "AllowedIPs = 10.0.1.0/24" in out
    assert "PersistentKeepalive = 25" in out


def test_mesh_plan_renders_all_pi_site_overlays(tmp_path, monkeypatch):
    (tmp_path / "styx.yaml").write_text(
        """
cluster:
  name: styx
nodes:
  - name: pegasus
    role: init-server
    hostname: pipegasus.duckdns.org
    public_ipv4: 203.0.113.10
  - name: atlas
    role: agent
    hostname: piatlas.duckdns.org
    public_ipv4: 203.0.113.10
  - name: hydra
    role: server
    hostname: pihydra.duckdns.org
    public_ipv4: 203.0.113.20
""",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    report, code = mesh_plan()
    assert code == 0
    out = render_mesh_report_text(report)
    assert "site overlays: StyxSite1=site 1 via pegasus:47821, StyxSite2=site 2 via hydra:47822" in out
    assert "--- pegasus [StyxSite1] ---" in out
    assert "Address = 10.0.1.10/24" in out
    assert "--- pegasus [StyxSite2] ---" in out
    assert "Address = 10.0.2.10/24" in out
    assert "--- hydra [StyxSite1] ---" in out
    assert "Address = 10.0.1.12/24" in out


def test_pistyx_clients_parses_and_skips_incomplete():
    cfg = {"clients": [
        {"name": "good", "public_key": "K", "ipv4": "10.0.250.2"},
        {"name": "no-key"},          # dropped: no public_key
        "not-a-dict",                 # dropped
    ]}
    clients = pistyx_clients(cfg)
    assert len(clients) == 1
    assert clients[0]["name"] == "good"
    assert clients[0]["host_suffix"] == 2


def test_pistyx_clients_rehomes_suffix_into_site_scope():
    cfg = {"clients": [{"name": "good", "public_key": "K", "ipv4": "10.0.250.7"}]}
    clients = pistyx_clients(cfg, site_index=2)
    assert clients[0]["host_suffix"] == 7
    assert clients[0]["ipv4"] == "10.0.2.7"
    assert clients[0]["ipv6"] == "fd00:cafe:0:2::7"


def test_site_index_is_public_ip_site_not_individual_node():
    nodes = parse_nodes({
        "nodes": [
            {"name": "pegasus", "public_ipv4": "203.0.113.10", "site_index": 7},
            {"name": "atlas", "public_ipv4": "203.0.113.10"},
            {"name": "hydra", "public_ipv4": "203.0.113.20"},
        ]
    })
    by_name = {node.name: node for node in nodes}
    assert _site_index_for_node(nodes, by_name["pegasus"]) == 7
    assert _site_index_for_node(nodes, by_name["atlas"]) == 7
    assert _site_index_for_node(nodes, by_name["hydra"]) == 1


def test_site_index_groups_distinct_public_ips_in_first_seen_order():
    nodes = parse_nodes({
        "nodes": [
            {"name": "pegasus", "public_ipv4": "203.0.113.10"},
            {"name": "atlas", "public_ipv4": "203.0.113.10"},
            {"name": "hydra", "public_ipv4": "203.0.113.20"},
        ]
    })
    by_name = {node.name: node for node in nodes}
    assert _site_index_for_node(nodes, by_name["pegasus"]) == 1
    assert _site_index_for_node(nodes, by_name["atlas"]) == 1
    assert _site_index_for_node(nodes, by_name["hydra"]) == 2
