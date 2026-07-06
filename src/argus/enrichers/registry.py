"""Enabled enrichers, driven by configuration: a provider without an API
key simply does not exist. Adding a provider = one class + one line here."""

from argus.core.config import get_settings
from argus.domain.enrichment import Enricher
from argus.enrichers.abuseipdb import AbuseIPDBEnricher
from argus.enrichers.virustotal import VirusTotalEnricher


def get_enrichers() -> list[Enricher]:
    settings = get_settings()
    enrichers: list[Enricher] = []
    if settings.virustotal_api_key:
        enrichers.append(VirusTotalEnricher(settings.virustotal_api_key))
    if settings.abuseipdb_api_key:
        enrichers.append(AbuseIPDBEnricher(settings.abuseipdb_api_key))
    return enrichers
