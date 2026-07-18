"""Enabled CTI providers, driven by config. abuse.ch providers need a free
Auth-Key; CISA KEV needs nothing. A provider without its key simply does
not exist. Adding a source (MISP, OTX, OpenCTI, commercial) = one class +
one line here."""

from argus.core.config import get_settings
from argus.cti.abuseipdb import AbuseIPDBIntelProvider
from argus.cti.cisa_kev import CISAKevProvider
from argus.cti.malwarebazaar import MalwareBazaarProvider
from argus.cti.threatfox import ThreatFoxProvider
from argus.cti.urlhaus import URLhausProvider
from argus.cti.virustotal import VirusTotalProvider
from argus.domain.cti import CTIProvider

# CISA KEV holds catalog state; instantiate once.
_KEV = CISAKevProvider()


def get_cti_providers() -> list[CTIProvider]:
    s = get_settings()
    providers: list[CTIProvider] = [_KEV]  # always on, no key
    if s.abuse_ch_auth_key:
        key = s.abuse_ch_auth_key
        providers.append(ThreatFoxProvider(key))
        providers.append(MalwareBazaarProvider(key))
        providers.append(URLhausProvider(key))
    if s.virustotal_api_key:
        providers.append(VirusTotalProvider(s.virustotal_api_key))
    if s.abuseipdb_api_key:
        providers.append(AbuseIPDBIntelProvider(s.abuseipdb_api_key))
    return providers
