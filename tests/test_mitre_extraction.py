"""Unit tests: ATT&CK technique ID extraction from event attributes."""

from types import SimpleNamespace

from argus.services.mitre import extract_technique_ids


def _event(attributes):
    return SimpleNamespace(attributes=attributes)


def test_list_form():
    assert extract_technique_ids(_event({"mitre_technique_ids": ["T1110", "T1059.001"]})) == [
        "T1059.001",
        "T1110",
    ]


def test_string_form_and_case():
    assert extract_technique_ids(_event({"mitre_technique_ids": "t1110, T1021"})) == [
        "T1021",
        "T1110",
    ]


def test_invalid_ids_dropped():
    assert extract_technique_ids(_event({"mitre_technique_ids": ["T11", "NOTATECH", "T1110"]})) == [
        "T1110"
    ]


def test_no_techniques():
    assert extract_technique_ids(_event({})) == []
