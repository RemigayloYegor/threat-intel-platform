"""Распознавание, валидация и нормализация индикаторов компрометации."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from tip.models import Indicator, IndicatorType

_HASH_RE = re.compile(r"^[a-fA-F0-9]+$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)
_EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@([a-z0-9.\-]+\.[a-z]{2,})$")
_HASH_LEN = {32: IndicatorType.MD5, 40: IndicatorType.SHA1, 64: IndicatorType.SHA256}

# Замены для "обезвреженных" (defanged) индикаторов: hxxp://1[.]2[.]3[.]4
_DEFANG = {
    "[.]": ".", "(.)": ".", "[dot]": ".", "{.}": ".",
    "[:]": ":", "[@]": "@", "(at)": "@", "[at]": "@",
    "hxxps": "https", "hxxp": "http", "fxp": "ftp",
}


def refang(value: str) -> str:
    """Вернуть индикатору исходный вид (обратно к defang)."""
    out = value.strip()
    for bad, good in _DEFANG.items():
        out = out.replace(bad, good)
    return out


def detect_type(value: str) -> IndicatorType | None:
    """Определить тип индикатора или None, если не распознан."""
    v = value.strip()
    if not v:
        return None
    if "/" in v or v.lower().startswith(("http://", "https://", "ftp://")):
        return IndicatorType.URL if _valid_url(v) else None
    if _HASH_RE.match(v) and len(v) in _HASH_LEN:
        return _HASH_LEN[len(v)]
    if "@" in v:
        return IndicatorType.EMAIL if _EMAIL_RE.match(v.lower()) else None
    try:
        ipaddress.ip_address(v)
        return IndicatorType.IP
    except ValueError:
        pass
    return IndicatorType.DOMAIN if _DOMAIN_RE.match(v.lower()) else None


def _valid_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return bool(parsed.scheme and parsed.netloc)


def normalize_value(value: str, itype: IndicatorType) -> str:
    """Нормализовать значение в зависимости от типа."""
    v = value.strip()
    if itype in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256):
        return v.lower()
    if itype in (IndicatorType.DOMAIN, IndicatorType.EMAIL):
        return v.lower().rstrip(".")
    if itype == IndicatorType.IP:
        return str(ipaddress.ip_address(v))
    if itype == IndicatorType.URL:
        parsed = urlparse(v)
        netloc = parsed.netloc.lower()
        return parsed._replace(netloc=netloc).geturl()
    return v


class NormalizationError(ValueError):
    """Значение не является валидным индикатором."""


def make_indicator(
    raw_value: str,
    source: str,
    confidence: int = 50,
    tags: set[str] | None = None,
    seen: datetime | None = None,
) -> Indicator:
    """Собрать нормализованный Indicator из сырого значения."""
    refanged = refang(raw_value)
    itype = detect_type(refanged)
    if itype is None:
        raise NormalizationError(f"не распознан индикатор: {raw_value[:80]!r}")
    ts = seen or datetime.now(timezone.utc)
    return Indicator(
        value=normalize_value(refanged, itype),
        type=itype,
        source=source,
        first_seen=ts,
        last_seen=ts,
        confidence=max(0, min(100, confidence)),
        tags=set(tags or ()),
        raw=raw_value.strip(),
    )


def dedup(indicators: list[Indicator]) -> list[Indicator]:
    """Схлопнуть дубликаты по ключу (тип, значение), объединяя метаданные."""
    merged: dict[tuple[str, str], Indicator] = {}
    for ind in indicators:
        if ind.key in merged:
            merged[ind.key].merge(ind)
        else:
            merged[ind.key] = ind
    return list(merged.values())


def extract_iocs(text: str) -> list[tuple[str, IndicatorType]]:
    """Вытащить из произвольного текста все распознаваемые индикаторы."""
    found: dict[str, IndicatorType] = {}
    for token in re.split(r"[\s,;\"'<>()\[\]{}]+", refang(text)):
        token = token.strip().rstrip(".,")
        if not token:
            continue
        itype = detect_type(token)
        # Значения вида "1.2.3.4:443" или "evil.com:8080" — отбрасываем :порт
        if itype is None and (m := re.match(r"^(.+):\d{1,5}$", token)):
            token = m.group(1)
            itype = detect_type(token)
        if itype is not None:
            found[normalize_value(token, itype)] = itype
    return list(found.items())
