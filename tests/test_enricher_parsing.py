"""Unit tests: provider response parsing (pure functions, no HTTP)."""

from argus.enrichers.abuseipdb import parse_abuseipdb
from argus.enrichers.virustotal import parse_vt_stats


def test_vt_malicious():
    data = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 12, "suspicious": 2, "harmless": 56, "undetected": 0}}}}
    score, verdict = parse_vt_stats(data)
    assert verdict == "malicious"
    assert score == round(12 / 70 * 100)


def test_vt_clean_and_missing():
    data = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 0, "harmless": 70}}}}
    assert parse_vt_stats(data) == (0, "clean")
    assert parse_vt_stats({}) == (None, "unknown")


def test_abuseipdb_thresholds():
    assert parse_abuseipdb({"data": {"abuseConfidenceScore": 100}}) == (100, "malicious")
    assert parse_abuseipdb({"data": {"abuseConfidenceScore": 30}}) == (30, "suspicious")
    assert parse_abuseipdb({"data": {"abuseConfidenceScore": 0}}) == (0, "clean")
    assert parse_abuseipdb({}) == (None, "unknown")
