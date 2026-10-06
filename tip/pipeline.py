"""Пайплайн обработки: обогащение всех индикаторов и расчёт оценок риска."""

from __future__ import annotations

from datetime import datetime

from tip.enrichment import Enricher, enrich_all
from tip.scoring import ScoringEngine
from tip.storage import Storage


def enrich_and_score(storage: Storage, enrichers: list[Enricher],
                     engine: ScoringEngine | None = None) -> tuple[int, int]:
    """Обогатить и оценить все индикаторы в хранилище.

    Возвращает (число обогащений, число оценок).
    """
    engine = engine or ScoringEngine()
    n_enrich = 0
    n_score = 0
    for indicator in storage.all_indicators():
        enrichments = enrich_all(indicator, enrichers)
        for enrichment in enrichments:
            storage.save_enrichment(enrichment)
            n_enrich += 1
        storage.save_score(engine.score(indicator, enrichments))
        n_score += 1
    return n_enrich, n_score


def build_demo_enrichers(now: datetime | None = None) -> list[Enricher]:
    """Собрать обогатители для демо: репутация и возраст домена из кампании."""
    from tip.enrichment import (
        DomainAgeEnricher,
        GeoIpEnricher,
        ReputationEnricher,
        StaticReputationProvider,
    )
    from tip.generator import CAMPAIGN

    known_bad = set(CAMPAIGN["ips"]) | set(CAMPAIGN["domains"]) | set(CAMPAIGN["hashes"])
    known_bad |= {"payload-host.example", "evil-c2.example"}
    providers = [
        StaticReputationProvider("vendor-a", known_bad),
        StaticReputationProvider("vendor-b", set(CAMPAIGN["ips"]) | set(CAMPAIGN["domains"])),
    ]
    young = CAMPAIGN["young_created"]

    def resolver(domain: str):
        return young.get(domain)

    return [
        GeoIpEnricher(),
        ReputationEnricher(providers),
        DomainAgeEnricher(resolver, now=now),
    ]
