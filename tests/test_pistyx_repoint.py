"""Pure tests for persisting the movable pistyx holder."""

from styxctl.pistyx_repoint import set_pistyx_current_host_text, write_pistyx_current_host


def test_set_pistyx_current_host_appends_missing_block():
    text = "cluster:\n  name: styx\n"
    out = set_pistyx_current_host_text(text, "hydra")
    assert out.endswith("\npistyx:\n  current_host: hydra\n")


def test_set_pistyx_current_host_replaces_existing_value():
    text = """cluster:
  name: styx
pistyx:
  public_key: PUB
  current_host: pegasus
nodes: []
"""
    out = set_pistyx_current_host_text(text, "hydra")
    assert "public_key: PUB" in out
    assert "current_host: hydra" in out
    assert "current_host: pegasus" not in out
    assert "nodes: []" in out


def test_set_pistyx_current_host_inserts_into_existing_block():
    text = """pistyx:
  public_key: PUB
nodes: []
"""
    out = set_pistyx_current_host_text(text, "hydra")
    assert out.startswith("pistyx:\n  current_host: hydra\n  public_key: PUB\n")


def test_write_pistyx_current_host_writes_backup(tmp_path):
    path = tmp_path / "styx.yaml"
    path.write_text("cluster:\n  name: styx\n", encoding="utf-8")

    report, code = write_pistyx_current_host("hydra", config_path=path)

    assert code == 0
    assert report["current_host"] == "hydra"
    assert (tmp_path / "styx.yaml.bak").exists()
    assert "current_host: hydra" in path.read_text(encoding="utf-8")
