from datetime import datetime, timezone

from tip.correlation import correlate
from tip.models import Enrichment
from tip.normalize import make_indicator

NOW = datetime(2026, 10, 6, tzinfo=timezone.utc)


def ind(value, tags=None):
    return make_indicator(value, "f", tags=tags, seen=NOW)


def test_shared_tag_forms_cluster():
    inds = [ind("evil-c2.example", {"c2"}), ind("45.155.205.99", {"c2"}),
            ind("good.example", {"benign"})]
    clusters = correlate(inds)
    assert len(clusters) == 1
    assert set(clusters[0].indicators) == {"evil-c2.example", "45.155.205.99"}
    assert any("c2" in r for r in clusters[0].reasons)


def test_singletons_excluded():
    inds = [ind("1.2.3.4", {"a"}), ind("5.6.7.8", {"b"})]
    assert correlate(inds) == []


def test_resolution_links_domain_and_ip():
    inds = [ind("evil-c2.example"), ind("45.155.205.99")]
    enrichments = {
        "evil-c2.example": [Enrichment("evil-c2.example", "resolution",
                                       {"ips": ["45.155.205.99"]}, NOW)],
        "45.155.205.99": [Enrichment("45.155.205.99", "resolution",
                                     {"ips": ["45.155.205.99"]}, NOW)],
    }
    clusters = correlate(inds, enrichments=enrichments)
    assert len(clusters) == 1
    assert any("45.155.205.99" in r for r in clusters[0].reasons)


def test_transitive_clustering():
    # a-b по тегу x, b-c по тегу y -> один кластер {a,b,c}
    inds = [ind("a.example", {"x"}), ind("b.example", {"x", "y"}), ind("c.example", {"y"})]
    clusters = correlate(inds)
    assert len(clusters) == 1
    assert len(clusters[0].indicators) == 3


def test_cluster_score_is_max():
    inds = [ind("a.example", {"c2"}), ind("b.example", {"c2"})]
    clusters = correlate(inds, scores={"a.example": 30, "b.example": 75})
    assert clusters[0].score == 75


def test_clusters_sorted_by_score():
    inds = [ind("a.example", {"t1"}), ind("b.example", {"t1"}),
            ind("c.example", {"t2"}), ind("d.example", {"t2"})]
    scores = {"a.example": 10, "b.example": 10, "c.example": 90, "d.example": 90}
    clusters = correlate(inds, scores=scores)
    assert [c.score for c in clusters] == [90, 10]
    assert [c.id for c in clusters] == [0, 1]
