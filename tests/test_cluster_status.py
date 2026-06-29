"""Pure tests for the Styx workload summarizer - no cluster, no SSH, no kubectl."""

from styxctl.cluster_status import summarize_styx_workloads


def _deploy(app: str, ready: int, replicas: int) -> dict:
    return {
        "kind": "Deployment",
        "metadata": {"labels": {"app.kubernetes.io/name": app, "app.kubernetes.io/managed-by": "styxctl"}},
        "status": {"readyReplicas": ready, "replicas": replicas},
    }


def _daemonset(app: str, ready: int, desired: int) -> dict:
    return {
        "kind": "DaemonSet",
        "metadata": {"labels": {"app.kubernetes.io/name": app, "app.kubernetes.io/managed-by": "styxctl"}},
        "status": {"numberReady": ready, "desiredNumberScheduled": desired},
    }


def test_empty_cluster_reports_every_service_absent():
    w = summarize_styx_workloads([])
    for key in ("duckdns", "resolver", "enforcer", "reresolve"):
        assert w[key]["present"] is False
        assert "not deployed" in w[key]["detail"]
    # the absent hint names the command that deploys each
    assert "styxctl deploy dns apply" in w["duckdns"]["detail"]
    assert "styxctl deploy resolver apply" in w["resolver"]["detail"]
    assert "styxctl deploy reresolve apply" in w["reresolve"]["detail"]


def test_all_services_present_and_ready():
    items = [
        _deploy("styx-duckdns", 1, 1),
        _daemonset("styx-resolver", 4, 4),
        _daemonset("styx-resolv-enforcer", 4, 4),
        _daemonset("styx-reresolve", 4, 4),
    ]
    w = summarize_styx_workloads(items)
    for key in ("duckdns", "resolver", "enforcer", "reresolve"):
        assert w[key]["present"] is True
        assert w[key]["ready"] == w[key]["desired"]
    assert w["resolver"]["detail"] == "4/4 ready"


def test_duckdns_aggregates_per_site_publishers():
    # one Deployment per site, pinned to each site's leader
    items = [_deploy("styx-duckdns", 1, 1), _deploy("styx-duckdns", 0, 1)]
    w = summarize_styx_workloads(items)
    assert w["duckdns"]["present"] is True
    assert w["duckdns"]["instances"] == 2
    assert w["duckdns"]["ready"] == 1
    assert w["duckdns"]["desired"] == 2
    assert "2 site publishers" in w["duckdns"]["detail"]


def test_degraded_daemonset_shows_partial_readiness():
    w = summarize_styx_workloads([_daemonset("styx-reresolve", 2, 4)])
    assert w["reresolve"]["present"] is True
    assert w["reresolve"]["ready"] == 2 and w["reresolve"]["desired"] == 4
    assert w["reresolve"]["detail"] == "2/4 ready"


def test_unlabeled_or_malformed_items_are_ignored():
    items = ["not-a-dict", {"metadata": {}}, _daemonset("styx-resolver", 1, 1)]
    w = summarize_styx_workloads(items)
    assert w["resolver"]["present"] is True
    assert w["enforcer"]["present"] is False
