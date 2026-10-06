"""Доменные модели платформы Threat Intelligence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class IndicatorType(str, Enum):
    """Тип индикатора компрометации (IOC)."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"


HASH_TYPES = frozenset({IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256})


class Severity(str, Enum):
    """Уровень критичности, рассчитанный скорингом."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Indicator:
    """Нормализованный индикатор компрометации."""

    value: str  # нормализованное значение
    type: IndicatorType
    source: str
    first_seen: datetime
    last_seen: datetime
    confidence: int = 50  # доверие к источнику, 0-100
    tags: set[str] = field(default_factory=set)
    raw: str = ""

    @property
    def key(self) -> tuple[str, str]:
        """Ключ дедупликации: (тип, значение)."""
        return (self.type.value, self.value)

    def merge(self, other: Indicator) -> None:
        """Объединить с дубликатом: расширить окно наблюдения, теги и доверие."""
        self.first_seen = min(self.first_seen, other.first_seen)
        self.last_seen = max(self.last_seen, other.last_seen)
        self.confidence = max(self.confidence, other.confidence)
        self.tags |= other.tags
        if other.source not in self.source.split(","):
            self.source = ",".join(sorted({*self.source.split(","), other.source}))


@dataclass(frozen=True)
class Enrichment:
    """Результат обогащения индикатора одним провайдером."""

    indicator: str
    provider: str
    data: dict
    ts: datetime


@dataclass(frozen=True)
class Score:
    """Оценка риска индикатора."""

    indicator: str
    score: int  # 0-100
    severity: Severity
    reasons: list[str]


@dataclass(frozen=True)
class Observation:
    """Наблюдение индикатора в телеметрии (sighting)."""

    indicator: str
    sensor: str
    context: str
    ts: datetime


@dataclass(frozen=True)
class Alert:
    """Срабатывание матчинга события по базе IOC."""

    ts: datetime
    indicator: str
    indicator_type: IndicatorType
    severity: Severity
    source: str
    context: str


@dataclass
class ThreatCluster:
    """Группа связанных индикаторов (кампания/угроза)."""

    id: int
    indicators: list[str]
    reasons: set[str] = field(default_factory=set)
    score: int = 0
