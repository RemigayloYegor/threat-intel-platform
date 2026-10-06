"""Базовый класс источника индикаторов (фида)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from tip.models import Indicator
from tip.normalize import NormalizationError, make_indicator


class Feed:
    """Источник индикаторов. Наследники реализуют parse()."""

    name: str = "base"
    default_confidence: int = 50
    default_tags: frozenset[str] = frozenset()

    def __init__(self, name: str | None = None, confidence: int | None = None,
                 tags: set[str] | None = None) -> None:
        self.name = name or self.name
        self.confidence = confidence if confidence is not None else self.default_confidence
        self.tags = set(tags) if tags is not None else set(self.default_tags)

    def parse(self, text: str) -> Iterator[Indicator]:
        """Разобрать содержимое фида в индикаторы."""
        raise NotImplementedError

    def load_text(self, text: str) -> list[Indicator]:
        """Разобрать текст, пропуская нераспознанные значения."""
        out = []
        for ind in self.parse(text):
            out.append(ind)
        return out

    def load_file(self, path: str | Path) -> list[Indicator]:
        """Загрузить индикаторы из файла."""
        return self.load_text(Path(path).read_text(encoding="utf-8", errors="replace"))

    def _make(self, value: str, extra_tags: set[str] | None = None,
              confidence: int | None = None) -> Indicator | None:
        """Создать индикатор с метаданными фида; None, если значение не IOC."""
        try:
            return make_indicator(
                value,
                source=self.name,
                confidence=self.confidence if confidence is None else confidence,
                tags=self.tags | (extra_tags or set()),
            )
        except NormalizationError:
            return None
