"""Indicator extraction from normalized events.

Rules that protect quota and signal quality:
- Only PUBLIC IPs are indicators (ip.is_global): asking VirusTotal about
  172.18.39.5 is meaningless and burns quota. Lab/corp-internal addresses
  matter for correlation, not reputation.
- Hashes are found by pattern anywhere in attributes (MD5/SHA1/SHA256),
  since vendors scatter them across differently named fields.
"""

import ipaddress
import re
from typing import Any

from argus.infrastructure.db.models import NormalizedEvent

_HASH_RE = re.compile(r"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _strings_in(obj: Any):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings_in(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings_in(v)


def extract_indicators(event: NormalizedEvent) -> list[tuple[str, str]]:
    """Returns deduplicated (indicator_type, value) pairs for one event."""
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for ip in (event.src_ip, event.dst_ip):
        if ip is None:
            continue
        value = str(ip)
        if _is_public_ip(value) and ("ip", value) not in seen:
            seen.add(("ip", value))
            found.append(("ip", value))

    for s in _strings_in(event.attributes or {}):
        for match in _HASH_RE.findall(s):
            key = ("hash", match.lower())
            if key not in seen:
                seen.add(key)
                found.append(key)

    return found
