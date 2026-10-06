"""Матчинг событий/логов по базе индикаторов компрометации."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import datetime, timezone

from tip.models import Alert, Indicator, Severity
from tip.normalize import extract_iocs
from tip.scoring import severity_from_score


class IocMatcher:
    """Проверяет наблюдаемые значения по множеству известных индикаторов."""

    def __init__(self, indicators: dict[str, Indicator], scores: dict[str, int] | None = None,
                 min_severity: Severity = Severity.INFO) -> None:
        self._index = indicators
        self._scores = scores or {}
        self._min = min_severity
        self._order = list(Severity)

    @classmethod
    def from_storage(cls, storage, min_severity: Severity = Severity.INFO) -> IocMatcher:
        """Построить матчер из хранилища."""
        indicators = {ind.value: ind for ind in storage.all_indicators()}
        scores = {ind.value: (s.score if (s := storage.get_score(ind.value)) else 0)
                  for ind in indicators.values()}
        return cls(indicators, scores, min_severity)

    def _severity(self, value: str) -> Severity:
        if value in self._scores:
            return severity_from_score(self._scores[value])
        return severity_from_score(self._index[value].confidence)

    def _passes(self, severity: Severity) -> bool:
        return self._order.index(severity) >= self._order.index(self._min)

    def match_text(self, text: str, sensor: str = "log",
                   ts: datetime | None = None) -> list[Alert]:
        """Найти в тексте значения из базы IOC и вернуть алерты."""
        ts = ts or datetime.now(timezone.utc)
        alerts = []
        for value, _itype in extract_iocs(text):
            ind = self._index.get(value)
            if ind is None:
                continue
            severity = self._severity(value)
            if not self._passes(severity):
                continue
            alerts.append(Alert(
                ts=ts, indicator=value, indicator_type=ind.type, severity=severity,
                source=ind.source, context=text.strip()[:200],
            ))
        return alerts

    def scan_lines(self, lines: Iterable[str], sensor: str = "log") -> Iterator[Alert]:
        """Прогнать строки лога через матчинг."""
        for line in lines:
            if line.strip():
                yield from self.match_text(line, sensor=sensor)
