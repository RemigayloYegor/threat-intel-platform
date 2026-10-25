"""Коллекторы источников индикаторов (фидов)."""

from __future__ import annotations

from tip.feeds.base import Feed
from tip.feeds.feodo import FeodoTrackerFeed
from tip.feeds.json_feed import MispOtxFeed, StixFeed
from tip.feeds.text_feed import CsvFeed, TextListFeed

# Реестр форматов для CLI: имя формата -> класс фида
FEED_FORMATS = {
    "txt": TextListFeed,
    "csv": CsvFeed,
    "stix": StixFeed,
    "misp": MispOtxFeed,
    "feodo": FeodoTrackerFeed,
}

__all__ = [
    "Feed",
    "TextListFeed",
    "CsvFeed",
    "StixFeed",
    "MispOtxFeed",
    "FeodoTrackerFeed",
    "FEED_FORMATS",
]
