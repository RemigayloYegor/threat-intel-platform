"""Обогащение IP: приватность, bogon и страна/ASN по встроенной таблице префиксов."""

from __future__ import annotations

import ipaddress

from tip.enrichment.base import Enricher
from tip.models import Enrichment, Indicator, IndicatorType

# Небольшая офлайн-таблица префикс -> (страна, ASN-владелец) для демонстрации.
# В продакшене заменяется на MaxMind GeoLite2 или аналог.
_PREFIX_TABLE: list[tuple[str, str, str]] = [
    ("8.8.8.0/24", "US", "AS15169 Google"),
    ("1.1.1.0/24", "US", "AS13335 Cloudflare"),
    ("185.220.100.0/22", "DE", "AS205100 Tor exit"),
    ("45.155.205.0/24", "NL", "AS206092 hosting"),
    ("91.240.118.0/24", "RU", "AS204428 hosting"),
    ("193.0.0.0/21", "NL", "AS3333 RIPE NCC"),
]


class GeoIpEnricher(Enricher):
    """Классификация IP и грубая геопривязка по таблице префиксов."""

    name = "geoip"
    supports = frozenset({IndicatorType.IP})

    def __init__(self, table: list[tuple[str, str, str]] | None = None) -> None:
        self._networks = [
            (ipaddress.ip_network(cidr), country, asn)
            for cidr, country, asn in (table if table is not None else _PREFIX_TABLE)
        ]

    def enrich(self, indicator: Indicator) -> Enrichment | None:
        """Определить приватность, bogon и, по возможности, страну/ASN IP."""
        try:
            ip = ipaddress.ip_address(indicator.value)
        except ValueError:
            return None
        country, asn = None, None
        for net, net_country, net_asn in self._networks:
            if ip in net:
                country, asn = net_country, net_asn
                break
        data = {
            "private": ip.is_private,
            "bogon": ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local,
            "country": country,
            "asn": asn,
            "version": ip.version,
        }
        return self._result(indicator, data)
