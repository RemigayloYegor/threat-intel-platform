"""Базовый интерфейс обогатителя индикаторов."""

from __future__ import annotations

from datetime import datetime, timezone

from tip.models import Enrichment, Indicator, IndicatorType


class Enricher:
    """Обогатитель индикатора дополнительными данными."""

    name: str = "base"
    supports: frozenset[IndicatorType] = frozenset()

    def applies_to(self, indicator: Indicator) -> bool:
        """Подходит ли обогатитель для данного типа индикатора."""
        return not self.supports or indicator.type in self.supports

    def enrich(self, indicator: Indicator) -> Enrichment | None:
        """Вернуть обогащение или None, если данных нет."""
        raise NotImplementedError

    def _result(self, indicator: Indicator, data: dict) -> Enrichment:
        return Enrichment(
            indicator=indicator.value,
            provider=self.name,
            data=data,
            ts=datetime.now(timezone.utc),
        )
