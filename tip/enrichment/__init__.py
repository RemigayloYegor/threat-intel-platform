"""Обогатители индикаторов и пайплайн обогащения."""

from __future__ import annotations

from collections.abc import Iterable

from tip.enrichment.base import Enricher
from tip.enrichment.geoip import GeoIpEnricher
from tip.enrichment.reputation import (
    ReputationEnricher,
    ReputationProvider,
    StaticReputationProvider,
)
from tip.enrichment.whois_age import DomainAgeEnricher
from tip.models import Enrichment, Indicator


def enrich_all(indicator: Indicator, enrichers: Iterable[Enricher]) -> list[Enrichment]:
    """Прогнать индикатор через подходящие обогатители."""
    out = []
    for enricher in enrichers:
        if enricher.applies_to(indicator):
            result = enricher.enrich(indicator)
            if result is not None:
                out.append(result)
    return out


__all__ = [
    "Enricher",
    "GeoIpEnricher",
    "ReputationEnricher",
    "ReputationProvider",
    "StaticReputationProvider",
    "DomainAgeEnricher",
    "enrich_all",
]
