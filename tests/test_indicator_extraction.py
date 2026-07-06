"""Unit tests: indicator extraction rules."""

from types import SimpleNamespace

from argus.services.indicators import extract_indicators


def _event(src_ip=None, dst_ip=None, attributes=None):
    return SimpleNamespace(src_ip=src_ip, dst_ip=dst_ip, attributes=attributes or {})


def test_public_ip_extracted_private_skipped():
    e = _event(src_ip="8.8.8.8", dst_ip="172.18.39.5")
    assert extract_indicators(e) == [("ip", "8.8.8.8")]  # lab IP excluded


def test_loopback_and_invalid_skipped():
    assert extract_indicators(_event(src_ip="127.0.0.1")) == []
    assert extract_indicators(_event(src_ip="not-an-ip")) == []


def test_hashes_found_anywhere_in_attributes():
    sha256 = "a" * 64
    md5 = "b" * 32
    e = _event(attributes={
        "command_line": f"certutil -hashfile x {sha256}",
        "nested": {"hashes": [f"MD5={md5}"]},
    })
    found = extract_indicators(e)
    assert ("hash", sha256) in found
    assert ("hash", md5) in found


def test_dedup():
    e = _event(src_ip="8.8.8.8", attributes={"a": "c" * 64, "b": "c" * 64})
    assert len(extract_indicators(e)) == 2  # one ip + one unique hash
