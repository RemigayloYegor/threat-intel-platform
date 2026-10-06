"""Движок оценки риска индикаторов на основе типа, источника и обогащения."""

from __future__ import annotations

from datetime import datetime, timezone

from tip.models import Enrichment, Indicator, IndicatorType, Score, Severity

# Базовый вес по типу индикатора (хеши и URL обычно конкретнее, чем один IP)
_TYPE_WEIGHT = {
    IndicatorType.SHA256: 35,
    IndicatorType.SHA1: 30,
    IndicatorType.MD5: 28,
    IndicatorType.URL: 32,
    IndicatorType.DOMAIN: 28,
    IndicatorType.EMAIL: 22,
    IndicatorType.IP: 24,
}
# Теги, повышающие риск
_HIGH_RISK_TAGS = {"c2", "apt", "ransomware", "malware", "phishing", "botnet", "exploit"}


def severity_from_score(score: int) -> Severity:
    """Отнести числовой балл (0-100) к уровню критичности."""
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 20:
        return Severity.LOW
    return Severity.INFO


class ScoringEngine:
    """Считает балл риска, складывая вклад типа, источника и обогащения."""

    def __init__(self, now: datetime | None = None, stale_days: int = 90) -> None:
        self._now = now
        self.stale_days = stale_days

    def _current(self) -> datetime:
        return self._now or datetime.now(timezone.utc)

    def score(self, indicator: Indicator, enrichments: list[Enrichment] | None = None) -> Score:
        """Рассчитать Score для индикатора с учётом его обогащений."""
        by_provider = {e.provider: e.data for e in (enrichments or [])}
        reasons: list[str] = []
        total = 0

        base = _TYPE_WEIGHT[indicator.type]
        total += base
        reasons.append(f"тип {indicator.type.value}: +{base}")

        conf = round(indicator.confidence * 0.2)
        total += conf
        reasons.append(f"доверие источника {indicator.confidence}: +{conf}")

        total += self._tag_contribution(indicator, reasons)
        total += self._reputation_contribution(by_provider, reasons)
        total += self._whois_contribution(by_provider, reasons)
        total += self._geoip_contribution(by_provider, reasons)
        total += self._recency_contribution(indicator, reasons)

        total = max(0, min(100, total))
        return Score(indicator.value, total, severity_from_score(total), reasons)

    def _tag_contribution(self, indicator: Indicator, reasons: list[str]) -> int:
        hits = sorted(indicator.tags & _HIGH_RISK_TAGS)
        if not hits:
            return 0
        bonus = min(30, 12 * len(hits))
        reasons.append(f"теги высокого риска {hits}: +{bonus}")
        return bonus

    def _reputation_contribution(self, by_provider: dict, reasons: list[str]) -> int:
        rep = by_provider.get("reputation")
        if not rep:
            return 0
        bonus = round(rep["ratio"] * 40)
        reasons.append(f"репутация {rep['malicious']}/{rep['total']}: +{bonus}")
        return bonus

    def _whois_contribution(self, by_provider: dict, reasons: list[str]) -> int:
        whois = by_provider.get("whois")
        if whois and whois.get("young"):
            reasons.append(f"молодой домен ({whois['age_days']} дн.): +15")
            return 15
        return 0

    def _geoip_contribution(self, by_provider: dict, reasons: list[str]) -> int:
        geo = by_provider.get("geoip")
        if geo and geo.get("bogon"):
            reasons.append("приватный/bogon IP, вероятно ложное срабатывание: -25")
            return -25
        return 0

    def _recency_contribution(self, indicator: Indicator, reasons: list[str]) -> int:
        last = indicator.last_seen
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        age = (self._current() - last).days
        if age > self.stale_days:
            reasons.append(f"не наблюдался {age} дн. (> {self.stale_days}): -10")
            return -10
        return 0
