"""Unit tests: the investigation prompt is grounded only in evidence."""

from argus.services.investigation import InvestigationContext, _render_prompt


def test_prompt_contains_evidence_and_instructions():
    ctx = InvestigationContext(
        evidence_id=1,
        summary="Host WS5. Techniques: T1003.001. Risk score 90.",
        techniques=[{"id": "T1003.001", "name": "LSASS Memory", "tactics": ["credential-access"]}],
        entities=[{"type": "process", "key": "lsass.exe"}],
        score=90,
        score_breakdown={"total": 90},
        similar=[{"host": "WS6", "score": 88, "techniques": ["T1003.001"], "similarity": 0.9}],
    )
    prompt = _render_prompt(ctx)
    assert "T1003.001" in prompt
    assert "LSASS Memory" in prompt
    assert "lsass.exe" in prompt
    assert "SIMILAR PAST EVIDENCE" in prompt  # RAG memory included
    assert "ALTERNATIVE EXPLANATIONS" in prompt  # explainability demanded
    assert "CONFIDENCE" in prompt
