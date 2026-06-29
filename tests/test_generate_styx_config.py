import importlib.util
from pathlib import Path


def _load_generate_module():
    path = Path(__file__).resolve().parents[1] / ".github" / "scripts" / "generate_styx_config.py"
    spec = importlib.util.spec_from_file_location("generate_styx_config", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_derive_nodes_preserves_template_hostname_and_site_metadata():
    module = _load_generate_module()
    runners = {
        "runners": [
            {
                "name": "pegasus",
                "status": "online",
                "labels": [{"name": "pegasus"}, {"name": "init-server"}],
            },
            {
                "name": "thor",
                "status": "online",
                "labels": [{"name": "thor"}, {"name": "agent"}],
            },
        ]
    }
    template = {
        "nodes": [
            {"name": "pegasus", "hostname": "pipegasus.duckdns.org", "site_index": 1},
            {"name": "thor", "hostname": "pithor.duckdns.org", "site_index": 2, "role": "server"},
        ]
    }

    nodes = module.derive_nodes(runners, template)

    assert nodes == [
        {"name": "pegasus", "role": "init-server", "hostname": "pipegasus.duckdns.org", "site_index": 1},
        {"name": "thor", "role": "agent", "hostname": "pithor.duckdns.org", "site_index": 2},
    ]
