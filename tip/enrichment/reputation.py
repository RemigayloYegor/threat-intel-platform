"""Обогащение репутацией: агрегация вердиктов нескольких провайдеров."""

from __future__ import annotations

from typing import Protocol

from tip.enrichment.base import Enricher
from tip.models import Enrichment, Indicator


class ReputationProvider(Protocol):
    """Провайдер репутации: отдаёт True, если индикатор считается вредоносным."""

    name: str

    def check(self, value: str) -> bool | None:
        """Вердикт по значению: True/False или None, если нет данных."""
        ...


class StaticReputationProvider:
    """Провайдер на основе заранее известного списка (для тестов/демо)."""

    def __init__(self, name: str, malicious: set[str]) -> None:
        self.name = name
        self._malicious = malicious

    def check(self, value: str) -> bool | None:
        """Вернуть True, если значение в чёрном списке провайдера."""
        return value in self._malicious


class ReputationEnricher(Enricher):
    """Опрашивает провайдеров и считает долю вредоносных вердиктов."""

    name = "reputation"

    def __init__(self, providers: list[ReputationProvider]) -> None:
        self.providers = providers

    def enrich(self, indicator: Indicator) -> Enrichment | None:
        """Собрать вердикты провайдеров в агрегированную репутацию."""
        votes: dict[str, bool] = {}
        for provider in self.providers:
            verdict = provider.check(indicator.value)
            if verdict is not None:
                votes[provider.name] = verdict
        if not votes:
            return None
        malicious = sum(1 for v in votes.values() if v)
        total = len(votes)
        data = {
            "malicious": malicious,
            "total": total,
            "ratio": round(malicious / total, 3),
            "providers": votes,
        }
        return self._result(indicator, data)
