"""Unit tests: CTI provider response parsing (pure functions, no HTTP)."""

from argus.cti.malwarebazaar import parse_malwarebazaar
from argus.cti.threatfox import parse_threatfox
from argus.cti.urlhaus import parse_urlhaus


def test_threatfox_found():
    data = {"query_status": "ok", "data": [
        {"id": "12345", "malware_printable": "Cobalt Strike",
         "confidence_level": 100, "first_seen": "2024-01-01", "tags": ["c2"]}]}
    f = parse_threatfox("1.2.3.4", "ip", data)
    assert f.found is True
    assert "Cobalt Strike" in f.malware
    assert f.reference_url == "https://threatfox.abuse.ch/ioc/12345/"


def test_threatfox_not_found():
    f = parse_threatfox("1.2.3.4", "ip", {"query_status": "no_result"})
    assert f.found is False
    assert f.reference_url is None


def test_malwarebazaar_found():
    data = {"query_status": "ok", "data": [
        {"sha256_hash": "abc", "signature": "Emotet", "file_type": "exe",
         "first_seen": "2024-02-02", "tags": ["emotet"]}]}
    f = parse_malwarebazaar("abc", data)
    assert f.found is True
    assert f.malware == ["Emotet"]
    assert "bazaar.abuse.ch" in f.reference_url


def test_urlhaus_found():
    data = {"query_status": "ok", "urls": [{"tags": ["phishing"]}],
            "firstseen": "2024-03-03", "urlhaus_reference": "https://urlhaus.abuse.ch/host/x/"}
    f = parse_urlhaus("evil.com", "domain", data)
    assert f.found is True
    assert f.reference_url.startswith("https://urlhaus.abuse.ch")
