"""Обогащение домена возрастом регистрации (молодые домены подозрительнее)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone

from tip.enrichment.base import Enricher
from tip.models import Enrichment, Indicator, IndicatorType

# Функция-резолвер: домен -> дата создания (или None). Инъектируется в тестах/проде.
WhoisResolver = Callable[[str], datetime | None]


class DomainAgeEnricher(Enricher):
    """Считает возраст домена в днях по дате регистрации из WHOIS."""

    name = "whois"
    supports = frozenset({IndicatorType.DOMAIN})

    def __init__(self, resolver: WhoisResolver, now: datetime | None = None) -> None:
        self.resolver = resolver
        self._now = now

    def _current(self) -> datetime:
        return self._now or datetime.now(timezone.utc)

    def enrich(self, indicator: Indicator) -> Enrichment | None:
        """Вернуть возраст домена и флаг 'молодой' (< 30 дней)."""
        created = self.resolver(indicator.value)
        if created is None:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = (self._current() - created).days
        data = {
            "created": created.date().isoformat(),
            "age_days": age_days,
            "young": age_days < 30,
        }
        return self._result(indicator, data)
