"""Unit tests: CTI provider response parsing (pure functions, no HTTP)."""

from argus.cti.abuseipdb import parse_abuseipdb_intel
from argus.cti.malwarebazaar import parse_malwarebazaar
from argus.cti.threatfox import parse_threatfox
from argus.cti.urlhaus import parse_urlhaus
from argus.cti.virustotal import parse_virustotal


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


def test_virustotal_flagged_ip():
    data = {"data": {"id": "1.2.3.4", "attributes": {
        "last_analysis_stats": {"malicious": 9, "suspicious": 1, "harmless": 60, "undetected": 20},
        "tags": ["tor"], "last_analysis_date": 1721000000}}}
    f = parse_virustotal("1.2.3.4", "ip", data)
    assert f.found is True
    assert f.confidence == 11  # 10 of 90 engines
    assert "10/90 engines" in f.summary
    assert f.reference_url == "https://www.virustotal.com/gui/ip-address/1.2.3.4"


def test_virustotal_clean_record_is_not_found():
    stats = {"malicious": 0, "suspicious": 0, "harmless": 54, "undetected": 37}
    data = {"data": {"id": "8.8.8.8", "attributes": {"last_analysis_stats": stats}}}
    f = parse_virustotal("8.8.8.8", "ip", data)
    assert f.found is False  # known to VT, but nobody flags it
    assert "0/91 engines" in f.summary


def test_virustotal_file_uses_threat_label_and_sha256():
    data = {"data": {"id": "xyz", "attributes": {
        "sha256": "deadbeef", "last_analysis_stats": {"malicious": 42, "undetected": 8},
        "popular_threat_classification": {"suggested_threat_label": "trojan.emotet"}}}}
    f = parse_virustotal("deadbeef", "hash", data)
    assert f.malware == ["trojan.emotet"]
    assert f.reference_url.endswith("/file/deadbeef")


def test_virustotal_404_is_truthful_not_found():
    f = parse_virustotal("nope.example", "domain", None)
    assert f.found is False
    assert f.summary == "No VirusTotal record."


def test_abuseipdb_reported_ip():
    data = {"data": {"abuseConfidenceScore": 87, "totalReports": 342, "isTor": True,
            "usageType": "Data Center/Web Hosting/Transit", "countryCode": "DE",
            "isp": "Evil Hosting GmbH", "lastReportedAt": "2026-07-17T09:00:00+00:00"}}
    f = parse_abuseipdb_intel("5.6.7.8", data)
    assert f.found is True
    assert f.confidence == 87
    assert "tor-exit" in f.tags
    assert f.last_seen == "2026-07-17"
    assert "342 report(s)" in f.summary
    assert f.reference_url == "https://www.abuseipdb.com/check/5.6.7.8"


def test_abuseipdb_clean_ip_is_not_found():
    data = {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}
    f = parse_abuseipdb_intel("9.9.9.9", data)
    assert f.found is False
    assert f.confidence == 0
