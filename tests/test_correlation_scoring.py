"""Unit tests: the explainable scoring function."""

from argus.services.correlation import _score


def test_critical_tactic_scores_high():
    score, bd = _score(
        techniques=["T1003.001", "T1059.001"],
        tactics=["credential-access", "execution"],
        event_count=100,
        max_conf=90,
    )
    assert bd["critical_tactic_bonus"] == 20
    assert bd["base_from_confidence"] == 36  # 90 * 0.4
    assert score == bd["total"]
    assert score > 60


def test_benign_single_technique_scores_low():
    score, bd = _score(
        techniques=["T1059.001"], tactics=["execution"], event_count=5, max_conf=50
    )
    assert bd["critical_tactic_bonus"] == 0
    assert score < 40


def test_score_clamped_to_100():
    score, _ = _score(
        techniques=["T" + str(i) for i in range(20)],
        tactics=list(_critical_all()),
        event_count=10000,
        max_conf=100,
    )
    assert score == 100


def _critical_all():
    return {"credential-access", "privilege-escalation", "lateral-movement",
            "exfiltration", "command-and-control", "execution", "discovery"}
