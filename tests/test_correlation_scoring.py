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
    assert bd["base_from_confidence"] == 22  # 90 * 0.25
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


def test_real_clusters_rank_not_saturate():
    """The core property: differently-sized real intrusions must NOT all
    peg at 100. Shapes taken from the APT29 evals, where the old weights
    scored a 47-event blip and a 3k-event full intrusion identically."""
    blip, _ = _score(
        techniques=["T1003.001", "T1053.005", "T1059.003"],
        tactics=["credential-access", "execution", "persistence", "privilege-escalation"],
        event_count=47,
        max_conf=90,
    )
    mid, _ = _score(
        techniques=["T1003.001", "T1053.005", "T1059.001", "T1059.003"],
        tactics=["credential-access", "execution", "persistence", "privilege-escalation"],
        event_count=424,
        max_conf=90,
    )
    full, _ = _score(
        techniques=[f"T{1000 + i}" for i in range(18)],
        tactics=["collection", "credential-access", "execution", "lateral-movement",
                 "persistence", "privilege-escalation", "stealth"],
        event_count=2547,
        max_conf=90,
    )
    assert blip < mid < full <= 100
