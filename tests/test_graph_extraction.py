"""Unit tests: entity + edge extraction from events."""

from types import SimpleNamespace

from argus.services.graph_builder import extract_graph


def _event(host=None, user=None, src_ip=None, dst_ip=None, attributes=None):
    return SimpleNamespace(
        host_name=host, user_name=user, src_ip=src_ip, dst_ip=dst_ip,
        attributes=attributes or {},
    )


def test_process_lineage_and_access():
    # Mimikatz-shaped: powershell spawned by explorer, accessing lsass
    e = _event(
        host="WS5",
        attributes={
            "process_image": "C:\\Windows\\System32\\powershell.exe",
            "parent_image": "C:\\Windows\\explorer.exe",
            "target_image": "C:\\Windows\\System32\\lsass.exe",
        },
    )
    ex = extract_graph(e)
    keys = {(n.entity_type, n.entity_key) for n in ex.nodes}
    assert ("process", "powershell.exe") in keys
    assert ("process", "lsass.exe") in keys
    assert ("host", "ws5") in keys
    assert ("process", "explorer.exe", "spawned", "process", "powershell.exe") in ex.edges
    assert ("process", "powershell.exe", "accessed", "process", "lsass.exe") in ex.edges


def test_network_edges():
    e = _event(host="web01", dst_ip="8.8.8.8")
    ex = extract_graph(e)
    assert ("host", "web01", "connected_to", "ip", "8.8.8.8") in ex.edges


def test_empty_event_no_nodes():
    assert extract_graph(_event()).nodes == []
