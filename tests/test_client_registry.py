"""Client registration tests - pure YAML edits plus mocked client config issuance."""

import pytest

from styxctl import wireguard_mesh
from styxctl.client_registry import merge_client, register_client, replace_clients_block


def test_merge_allocates_next_free_client_suffix():
    clients = [{"name": "old", "public_key": "OLD", "host_suffix": 64}]
    merged, suffix = merge_client(clients, "new", "NEW")
    assert suffix == 65
    assert [c["name"] for c in merged] == ["old", "new"]


def test_merge_rejects_suffix_collision():
    clients = [{"name": "old", "public_key": "OLD", "host_suffix": 64}]
    with pytest.raises(ValueError, match="already used by client old"):
        merge_client(clients, "new", "NEW", suffix=64)


def test_merge_moves_legacy_pi_band_client_to_client_band():
    merged, suffix = merge_client(
        [{"name": "phone", "public_key": "OLD", "host_suffix": 2}],
        "phone",
        "NEW",
    )
    assert suffix == 64
    assert merged[0]["public_key"] == "NEW"


def test_replace_clients_block_preserves_other_top_level_content():
    text = """# styx
cluster:
  name: styx
clients:
  - name: old
    public_key: OLD
nodes:
  - name: pegasus
"""
    new_text = replace_clients_block(
        text,
        'clients:\n  - name: new\n    public_key: "NEW"\n    host_suffix: 64\n',
    )
    assert new_text.startswith("# styx\ncluster:")
    assert "name: old" not in new_text
    assert "name: new" in new_text
    assert "nodes:\n  - name: pegasus" in new_text


def test_register_client_writes_backup_and_clients_block(tmp_path):
    path = tmp_path / "styx.yaml"
    path.write_text(
        """cluster:
  name: styx
nodes: []
""",
        encoding="utf-8",
    )

    report, code = register_client("phone", "PUB", config_path=path)

    assert code == 0
    assert report["host_suffix"] == 64
    assert (tmp_path / "styx.yaml.bak").exists()
    text = path.read_text(encoding="utf-8")
    assert 'public_key: "PUB"' in text
    assert "host_suffix: 64" in text
    assert "nodes: []" in text


def test_client_config_registers_and_renders_matching_suffix(tmp_path, monkeypatch):
    path = tmp_path / "styx.yaml"
    path.write_text(
        """cluster:
  name: styx
pistyx:
  public_key: PISTYX_PUB
nodes:
  - name: pegasus
    role: init-server
    hostname: pipegasus.duckdns.org
    public_ipv4: 203.0.113.10
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(wireguard_mesh, "_gen_private_key", lambda: "CLIENT_PRIV")
    monkeypatch.setattr(wireguard_mesh, "_public_key", lambda private: "CLIENT_PUB")

    report, code = wireguard_mesh.client_config("phone", config_path=path, register=True)

    assert code == 0, report
    assert report["host_suffix"] == 64
    assert "Address = 10.0.1.64/32" in report["config"]
    assert "PrivateKey = CLIENT_PRIV" in report["config"]
    text = path.read_text(encoding="utf-8")
    assert 'public_key: "CLIENT_PUB"' in text
    assert "host_suffix: 64" in text


def test_client_config_register_auto_allocates_next_suffix(tmp_path, monkeypatch):
    path = tmp_path / "styx.yaml"
    path.write_text(
        """cluster:
  name: styx
pistyx:
  public_key: PISTYX_PUB
clients:
  - name: laptop
    public_key: LAPTOP_PUB
    host_suffix: 64
nodes:
  - name: pegasus
    role: init-server
    hostname: pipegasus.duckdns.org
    public_ipv4: 203.0.113.10
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(wireguard_mesh, "_gen_private_key", lambda: "CLIENT_PRIV")
    monkeypatch.setattr(wireguard_mesh, "_public_key", lambda private: "CLIENT_PUB")

    report, code = wireguard_mesh.client_config("phone", config_path=path, register=True)

    assert code == 0, report
    assert report["host_suffix"] == 65
    assert "Address = 10.0.1.65/32" in report["config"]
