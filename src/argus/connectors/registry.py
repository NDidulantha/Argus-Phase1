"""Maps a source identifier to its normalizer.

Unknown sources are NOT rejected: ARGUS always stores the raw event
(evidence preservation) and simply skips normalization until a connector
for that vendor exists. Adding a vendor = one normalizer class + one line.
"""

from argus.connectors.evtx_normalizer import EvtxNormalizer
from argus.connectors.mordor import MordorNormalizer
from argus.connectors.wazuh import WazuhNormalizer
from argus.domain.events import EventNormalizer

_NORMALIZERS: dict[str, EventNormalizer] = {
    WazuhNormalizer.source_type: WazuhNormalizer(),
    MordorNormalizer.source_type: MordorNormalizer(),
    EvtxNormalizer.source_type: EvtxNormalizer(),
}


def get_normalizer(source: str) -> EventNormalizer | None:
    return _NORMALIZERS.get(source)
