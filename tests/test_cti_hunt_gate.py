"""The hunt-lead gate: separate real leads from 'merely seen before'.

found=True only means a feed has a record. For the reputation-scored feeds
that includes single-engine VirusTotal false positives on well-known CDNs and
stray AbuseIPDB reports at confidence 0. _is_lead gates those on real signal
while trusting curated feeds (abuse.ch, KEV) on found alone.
"""

from argus.domain.cti import CTIFinding
from argus.services.cti_hunt import _is_lead


def _vt(engines: int) -> CTIFinding:
    return CTIFinding(
        provider="virustotal", indicator_type="ip", indicator_value="1.2.3.4",
        found=engines > 0, confidence=engines,
        raw={"stats": {"malicious": engines, "suspicious": 0}},
    )


def _abuse(score: int, reports: int = 1) -> CTIFinding:
    return CTIFinding(
        provider="abuseipdb", indicator_type="ip", indicator_value="1.2.3.4",
        found=reports > 0, confidence=score,
    )


def test_not_found_is_never_a_lead():
    assert _is_lead(_vt(0)) is False


def test_lone_virustotal_engine_is_noise():
    # 1/91 engines on a well-known CDN — the exact false positive we saw.
    assert _is_lead(_vt(1)) is False


def test_two_virustotal_engines_qualifies():
    # a weak-but-real signal; emerging C2 often has only a handful of engines.
    assert _is_lead(_vt(2)) is True
    assert _is_lead(_vt(8)) is True


def test_abuseipdb_zero_confidence_is_noise():
    assert _is_lead(_abuse(0)) is False
    assert _is_lead(_abuse(24)) is False


def test_abuseipdb_meaningful_confidence_qualifies():
    assert _is_lead(_abuse(25)) is True
    assert _is_lead(_abuse(93)) is True


def test_curated_feed_trusted_on_found_alone():
    # abuse.ch / KEV: a hit is already a real IOC, no engine/score to gate on.
    tf = CTIFinding(
        provider="threatfox", indicator_type="ip", indicator_value="1.2.3.4",
        found=True, confidence=None,
    )
    assert _is_lead(tf) is True
