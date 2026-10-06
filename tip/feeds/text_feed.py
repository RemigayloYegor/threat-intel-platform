"""Фиды в текстовых форматах: список строк и CSV."""

from __future__ import annotations

import csv
import io
from collections.abc import Iterator

from tip.feeds.base import Feed
from tip.models import Indicator


class TextListFeed(Feed):
    """Простой список: один индикатор в строке, '#' — комментарий."""

    name = "textlist"

    def parse(self, text: str) -> Iterator[Indicator]:
        """Разобрать построчный список индикаторов."""
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            ind = self._make(line.split()[0])
            if ind is not None:
                yield ind


class CsvFeed(Feed):
    """CSV-фид с настраиваемыми колонками значения, доверия и тегов."""

    name = "csv"

    def __init__(self, value_col: str = "indicator", confidence_col: str | None = "confidence",
                 tags_col: str | None = "tags", **kwargs) -> None:
        super().__init__(**kwargs)
        self.value_col = value_col
        self.confidence_col = confidence_col
        self.tags_col = tags_col

    def parse(self, text: str) -> Iterator[Indicator]:
        """Разобрать CSV, извлекая значение, доверие и теги из колонок."""
        reader = csv.DictReader(io.StringIO(text))
        if reader.fieldnames is None or self.value_col not in reader.fieldnames:
            return
        for row in reader:
            value = (row.get(self.value_col) or "").strip()
            if not value:
                continue
            confidence = None
            if self.confidence_col and (raw := row.get(self.confidence_col)):
                try:
                    confidence = int(float(raw))
                except ValueError:
                    confidence = None
            extra = set()
            if self.tags_col and (raw := row.get(self.tags_col)):
                extra = {t.strip().lower() for t in raw.replace(";", ",").split(",") if t.strip()}
            ind = self._make(value, extra_tags=extra, confidence=confidence)
            if ind is not None:
                yield ind
