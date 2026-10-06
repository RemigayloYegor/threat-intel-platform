from datetime import datetime, timezone

import pytest

from tip.models import Enrichment, Severity
from tip.normalize import make_indicator
from tip.scoring import ScoringEngine, severity_from_score

NOW = datetime(2026, 10, 6, tzinfo=timezone.utc)
ENGINE = ScoringEngine(now=NOW)


def ind(value="45.155.205.99", confidence=50, tags=None, seen=NOW):
    return make_indicator(value, "f", confidence=confidence, tags=tags, seen=seen)


def enr(provider, data):
    return Enrichment("45.155.205.99", provider, data, NOW)


def test_base_score_ip():
    # IP(24) + доверие 50*0.2=10 = 34, без обогащений
    s = ENGINE.score(ind())
    assert s.score == 34
    assert s.severity == Severity.LOW


def test_reputation_raises_score():
    s = ENGINE.score(ind(), [enr("reputation", {"malicious": 2, "total": 2, "ratio": 1.0})])
    assert s.score == 74
    assert s.severity == Severity.HIGH
    assert any("репутация" in r for r in s.reasons)


def test_high_risk_tags_add_points():
    assert ENGINE.score(ind(tags={"c2"})).score == 46
    assert ENGINE.score(ind(tags={"c2", "malware"})).score == 58


def test_young_domain_bonus():
    dom = make_indicator("evil.example", "f", confidence=50, seen=NOW)
    s = ENGINE.score(dom, [enr("whois", {"young": True, "age_days": 5})])
    # domain(28) + 10 + 15 = 53
    assert s.score == 53
    assert any("молодой домен" in r for r in s.reasons)


def test_bogon_ip_penalty():
    s = ENGINE.score(ind("10.0.0.5"), [enr("geoip", {"bogon": True, "private": True})])
    assert s.score == 9
    assert s.severity == Severity.INFO


def test_stale_indicator_penalty():
    old = ind(seen=datetime(2026, 1, 1, tzinfo=timezone.utc))
    s = ENGINE.score(old)
    assert any("не наблюдался" in r for r in s.reasons)
    assert s.score == 24


def test_score_clamped_to_100():
    loud = ind(confidence=100, tags={"c2", "apt", "ransomware"})
    s = ENGINE.score(loud, [enr("reputation", {"malicious": 3, "total": 3, "ratio": 1.0})])
    assert s.score == 100


@pytest.mark.parametrize("score,sev", [
    (0, Severity.INFO), (19, Severity.INFO), (20, Severity.LOW), (40, Severity.MEDIUM),
    (60, Severity.HIGH), (80, Severity.CRITICAL), (100, Severity.CRITICAL),
])
def test_severity_buckets(score, sev):
    assert severity_from_score(score) == sev
