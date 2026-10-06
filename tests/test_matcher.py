from datetime import datetime, timezone

from tip.matcher import IocMatcher
from tip.models import Score, Severity
from tip.normalize import make_indicator
from tip.storage import Storage

NOW = datetime(2026, 10, 6, tzinfo=timezone.utc)


def build_index(values_tags):
    return {v: make_indicator(v, "feed", tags=t, seen=NOW) for v, t in values_tags}


def test_match_text_finds_known_ioc():
    index = build_index([("45.155.205.99", {"c2"})])
    matcher = IocMatcher(index, scores={"45.155.205.99": 70})
    alerts = matcher.match_text("firewall: 10.0.0.5 -> 45.155.205.99:443", ts=NOW)
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH


def test_no_match_for_unknown():
    matcher = IocMatcher(build_index([("45.155.205.99", set())]))
    assert matcher.match_text("clean traffic to 8.8.8.8") == []


def test_min_severity_filter():
    index = build_index([("45.155.205.99", set())])
    matcher = IocMatcher(index, scores={"45.155.205.99": 25},  # low
                         min_severity=Severity.HIGH)
    assert matcher.match_text("to 45.155.205.99") == []


def test_defanged_match():
    matcher = IocMatcher(build_index([("45.155.205.99", set())]),
                         scores={"45.155.205.99": 50})
    assert len(matcher.match_text("beacon 45[.]155[.]205[.]99")) == 1


def test_scan_lines_multiple():
    index = build_index([("evil.example", set()), ("45.155.205.99", set())])
    matcher = IocMatcher(index, scores={"evil.example": 50, "45.155.205.99": 50})
    lines = ["dns evil.example", "", "clean 8.8.8.8", "conn 45.155.205.99"]
    alerts = list(matcher.scan_lines(lines))
    assert {a.indicator for a in alerts} == {"evil.example", "45.155.205.99"}


def test_from_storage():
    store = Storage(":memory:")
    store.upsert_indicators([make_indicator("45.155.205.99", "feed", seen=NOW)])
    store.save_score(Score("45.155.205.99", 90, Severity.CRITICAL, []))
    matcher = IocMatcher.from_storage(store)
    alerts = matcher.match_text("to 45.155.205.99")
    assert alerts[0].severity == Severity.CRITICAL
    store.close()
