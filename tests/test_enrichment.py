from datetime import datetime, timezone

from tip.enrichment import (
    DomainAgeEnricher,
    GeoIpEnricher,
    ReputationEnricher,
    StaticReputationProvider,
    enrich_all,
)
from tip.normalize import make_indicator

NOW = datetime(2026, 10, 6, tzinfo=timezone.utc)


def ip(value="45.155.205.99"):
    return make_indicator(value, "f")


def domain(value="evil.example"):
    return make_indicator(value, "f")


def test_geoip_public_ip_with_country():
    e = GeoIpEnricher().enrich(ip("8.8.8.8"))
    assert e.data["country"] == "US" and e.data["private"] is False
    assert e.data["bogon"] is False


def test_geoip_private_ip_is_bogon():
    e = GeoIpEnricher().enrich(ip("10.0.0.5"))
    assert e.data["private"] is True and e.data["bogon"] is True
    assert e.data["country"] is None


def test_geoip_only_applies_to_ip():
    assert GeoIpEnricher().applies_to(ip())
    assert not GeoIpEnricher().applies_to(domain())


def test_reputation_aggregates_votes():
    providers = [
        StaticReputationProvider("a", {"45.155.205.99"}),
        StaticReputationProvider("b", {"45.155.205.99"}),
        StaticReputationProvider("c", set()),
    ]
    e = ReputationEnricher(providers).enrich(ip())
    assert e.data["malicious"] == 2 and e.data["total"] == 3
    assert e.data["ratio"] == round(2 / 3, 3)


def test_reputation_none_when_no_provider_knows():
    providers = [StaticReputationProvider("a", set())]
    # провайдер отвечает False (знает, но чисто) -> total=1, ratio 0
    e = ReputationEnricher(providers).enrich(ip())
    assert e.data["ratio"] == 0.0


def test_domain_age_young():
    created = datetime(2026, 9, 25, tzinfo=timezone.utc)
    e = DomainAgeEnricher(lambda d: created, now=NOW).enrich(domain())
    assert e.data["young"] is True and e.data["age_days"] == 11


def test_domain_age_old():
    created = datetime(2015, 1, 1, tzinfo=timezone.utc)
    e = DomainAgeEnricher(lambda d: created, now=NOW).enrich(domain())
    assert e.data["young"] is False


def test_domain_age_no_data():
    assert DomainAgeEnricher(lambda d: None, now=NOW).enrich(domain()) is None


def test_enrich_all_applies_only_matching():
    enrichers = [GeoIpEnricher(), DomainAgeEnricher(lambda d: NOW, now=NOW)]
    results = enrich_all(ip("8.8.8.8"), enrichers)
    assert {r.provider for r in results} == {"geoip"}
