"""Реальный фид abuse.ch Feodo Tracker: C2-адреса ботнетов (Emotet, QakBot и др.).

Публичный CSV без API-ключа. Поддерживает разбор сохранённого файла (офлайн, для тестов)
и загрузку актуального списка по сети (fetch_text).
"""

from __future__ import annotations

import csv
import io
import urllib.request
from collections.abc import Iterator

from tip.feeds.base import Feed
from tip.models import Indicator

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"


class FeodoTrackerFeed(Feed):
    """C2-IP ботнетов из Feodo Tracker (abuse.ch).

    Формат CSV: first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware.
    Строки-комментарии начинаются с '#'.
    """

    name = "feodo"
    default_confidence = 75
    default_tags = frozenset({"c2", "botnet"})

    def parse(self, text: str) -> Iterator[Indicator]:
        """Разобрать CSV Feodo Tracker в индикаторы-IP с тегами малвари и статуса C2."""
        rows = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
        if not rows:
            return
        reader = csv.DictReader(io.StringIO("\n".join(rows)))
        for row in reader:
            ip = (row.get("dst_ip") or "").strip()
            if not ip:
                continue
            extra = set()
            if malware := (row.get("malware") or "").strip():
                extra.add(malware.lower())
            status = (row.get("c2_status") or "").strip().lower()
            if status:
                extra.add(f"c2-{status}")
            # Активные C2 опаснее отключённых
            confidence = 90 if status == "online" else 60
            if port := (row.get("dst_port") or "").strip():
                extra.add(f"port-{port}")
            ind = self._make(ip, extra_tags=extra, confidence=confidence)
            if ind is not None:
                yield ind

    @staticmethod
    def fetch_text(url: str = FEODO_URL, timeout: float = 30.0) -> str:
        """Загрузить актуальный CSV Feodo Tracker по сети."""
        req = urllib.request.Request(url, headers={"User-Agent": "tip-feodo/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")

    def load_live(self, url: str = FEODO_URL) -> list[Indicator]:
        """Скачать и разобрать актуальный список (требует сети)."""
        return self.load_text(self.fetch_text(url))
