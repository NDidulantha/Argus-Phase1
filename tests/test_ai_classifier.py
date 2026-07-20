"""AI classifier parsing/validation — the deterministic value-add, no LLM.

The single provider.complete() call is the only non-deterministic part; the
guardrails around it (extract JSON, drop hallucinated ids, cap confidence)
are pure and must be airtight, since they are what keep a chatty model from
polluting the technique table.
"""

from argus.services.ai_classifier import _extract_json_array, parse_proposals

CATALOG = {"T1059.001", "T1105", "T1003", "T1021.002"}


def test_extract_plain_array():
    assert _extract_json_array('[{"technique_id":"T1105"}]') == [{"technique_id": "T1105"}]


def test_extract_from_fenced_and_prose():
    text = 'Here is the result:\n```json\n[{"technique_id":"T1105","confidence":40}]\n```\nDone.'
    assert _extract_json_array(text) == [{"technique_id": "T1105", "confidence": 40}]


def test_extract_garbage_is_empty():
    assert _extract_json_array("no json here") == []
    assert _extract_json_array("") == []
    assert _extract_json_array("{not: valid}") == []


def test_valid_proposal_kept_and_capped():
    out = parse_proposals(
        '[{"technique_id":"T1105","confidence":90,"rationale":"downloads a payload"}]',
        CATALOG, cap=50,
    )
    assert len(out) == 1
    assert out[0].technique_id == "T1105"
    assert out[0].confidence == 50  # capped below the rules floor
    assert "payload" in out[0].rationale


def test_hallucinated_id_dropped():
    # T9999 is well-formed but not in the catalog -> dropped
    out = parse_proposals(
        '[{"technique_id":"T9999","confidence":80},{"technique_id":"T1003","confidence":30}]',
        CATALOG, cap=50,
    )
    assert [p.technique_id for p in out] == ["T1003"]
    assert out[0].confidence == 30  # under the cap -> unchanged


def test_malformed_id_dropped():
    out = parse_proposals(
        '[{"technique_id":"T12","confidence":40},{"technique_id":"not-an-id","confidence":40}]',
        CATALOG, cap=50,
    )
    assert out == []


def test_lowercase_id_normalized():
    out = parse_proposals('[{"technique_id":"t1059.001","confidence":20}]', CATALOG, cap=50)
    assert [p.technique_id for p in out] == ["T1059.001"]


def test_duplicate_technique_deduped():
    out = parse_proposals(
        '[{"technique_id":"T1105","confidence":40},{"technique_id":"T1105","confidence":45}]',
        CATALOG, cap=50,
    )
    assert len(out) == 1


def test_bad_confidence_defaults_low():
    out = parse_proposals('[{"technique_id":"T1105","confidence":"high"}]', CATALOG, cap=50)
    assert len(out) == 1
    assert out[0].confidence == 1  # unparseable -> clamped to the 1 floor


def test_non_list_response_is_empty():
    assert parse_proposals('{"technique_id":"T1105"}', CATALOG, cap=50) == []
