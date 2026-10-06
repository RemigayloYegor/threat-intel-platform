from datetime import datetime, timezone

import pytest

from tip.models import Alert, Enrichment, IndicatorType, Score, Severity
from tip.normalize import make_indicator
from tip.storage import Storage

NOW = datetime(2026, 10, 6, tzinfo=timezone.utc)


@pytest.fixture
def store():
    s = Storage(":memory:")
    yield s
    s.close()


def ind(value="45.155.205.99", confidence=50, tags=None, seen=NOW):
    return make_indicator(value, "feed", confidence=confidence, tags=tags, seen=seen)


def test_upsert_and_get(store):
    store.upsert_indicators([ind(tags={"c2"})])
    got = store.get_indicator("45.155.205.99")
    assert got.type == IndicatorType.IP and got.tags == {"c2"}


def test_upsert_merges_duplicate(store):
    store.upsert_indicators([ind(confidence=40, tags={"scan"})])
    store.upsert_indicators([ind(confidence=80, tags={"c2"})])
    got = store.get_indicator("45.155.205.99")
    assert got.confidence == 80
    assert got.tags == {"scan", "c2"}
    assert store.stats()["indicators"] == 1


def test_search_filters(store):
    store.upsert_indicators([
        ind("45.155.205.99", tags={"c2"}),
        make_indicator("evil.example", "feed", tags={"phishing"}, seen=NOW),
    ])
    store.save_score(Score("45.155.205.99", 70, Severity.HIGH, []))
    assert len(store.search(itype=IndicatorType.IP)) == 1
    assert len(store.search(tag="phishing")) == 1
    assert len(store.search(min_score=50)) == 1
    assert store.search(min_score=50)[0]["value"] == "45.155.205.99"


def test_enrichment_roundtrip_and_upsert(store):
    store.save_enrichment(Enrichment("45.155.205.99", "geoip", {"country": "NL"}, NOW))
    store.save_enrichment(Enrichment("45.155.205.99", "geoip", {"country": "DE"}, NOW))
    enrichments = store.get_enrichments("45.155.205.99")
    assert len(enrichments) == 1
    assert enrichments[0].data["country"] == "DE"


def test_score_roundtrip(store):
    store.save_score(Score("45.155.205.99", 88, Severity.CRITICAL, ["r1", "r2"]))
    s = store.get_score("45.155.205.99")
    assert s.score == 88 and s.severity == Severity.CRITICAL and s.reasons == ["r1", "r2"]


def test_alerts_and_stats(store):
    store.upsert_indicators([ind()])
    store.save_score(Score("45.155.205.99", 70, Severity.HIGH, []))
    store.save_alerts([Alert(NOW, "45.155.205.99", IndicatorType.IP, Severity.HIGH,
                             "feed", "ctx")])
    stats = store.stats()
    assert stats["indicators"] == 1 and stats["alerts"] == 1
    assert stats["by_type"]["ip"] == 1
    assert stats["by_severity"]["high"] == 1
    assert store.recent_alerts()[0]["value"] == "45.155.205.99"


def test_get_missing_returns_none(store):
    assert store.get_indicator("nope") is None
    assert store.get_score("nope") is None
