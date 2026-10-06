"""Фиды в JSON: минимальный STIX 2.1 и MISP/OTX-подобный формат."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator

from tip.feeds.base import Feed
from tip.models import Indicator

# Значения в STIX-паттерне заключены в одинарные кавычки:
# [ipv4-addr:value = '1.2.3.4'], [file:hashes.'SHA-256' = 'abc...']
_STIX_QUOTED = re.compile(r"'([^']+)'")


class StixFeed(Feed):
    """Разбор STIX 2.1 bundle: объекты type='indicator' с полем pattern."""

    name = "stix"

    def parse(self, text: str) -> Iterator[Indicator]:
        """Извлечь индикаторы из STIX-бандла."""
        try:
            bundle = json.loads(text)
        except json.JSONDecodeError:
            return
        for obj in bundle.get("objects", []):
            if obj.get("type") != "indicator":
                continue
            labels = {str(label).lower() for label in obj.get("labels", [])}
            confidence = obj.get("confidence")
            # Каждое значение в кавычках проверяем на индикатор; служебные
            # токены вроде 'SHA-256' не распознаются и отсеиваются в _make().
            for value in _STIX_QUOTED.findall(obj.get("pattern", "")):
                ind = self._make(value, extra_tags=labels, confidence=confidence)
                if ind is not None:
                    yield ind


class MispOtxFeed(Feed):
    """MISP/OTX-подобный JSON: список объектов с value и опциональными тегами."""

    name = "misp"

    def __init__(self, value_key: str = "indicator", tags_key: str = "tags",
                 confidence_key: str = "confidence", items_key: str | None = None,
                 **kwargs) -> None:
        super().__init__(**kwargs)
        self.value_key = value_key
        self.tags_key = tags_key
        self.confidence_key = confidence_key
        self.items_key = items_key

    def parse(self, text: str) -> Iterator[Indicator]:
        """Извлечь индикаторы из JSON-списка объектов."""
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        items = data.get(self.items_key, []) if isinstance(data, dict) else data
        if self.items_key is None and isinstance(data, dict):
            items = data.get("results") or data.get("data") or []
        for obj in items:
            if not isinstance(obj, dict):
                continue
            value = str(obj.get(self.value_key, "")).strip()
            if not value:
                continue
            raw_tags = obj.get(self.tags_key) or []
            if isinstance(raw_tags, str):
                raw_tags = raw_tags.split(",")
            extra = {str(t).strip().lower() for t in raw_tags if str(t).strip()}
            confidence = obj.get(self.confidence_key)
            try:
                confidence = int(confidence) if confidence is not None else None
            except (ValueError, TypeError):
                confidence = None
            ind = self._make(value, extra_tags=extra, confidence=confidence)
            if ind is not None:
                yield ind
