"""Корреляция индикаторов в кластеры угроз по общим признакам."""

from __future__ import annotations

from collections import defaultdict

from tip.models import Enrichment, Indicator, ThreatCluster


class _UnionFind:
    """Система непересекающихся множеств для группировки связанных индикаторов."""

    def __init__(self, items: list[str]) -> None:
        self.parent = {item: item for item in items}

    def find(self, x: str) -> str:
        """Найти представителя множества со сжатием пути."""
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        """Объединить множества двух элементов."""
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def correlate(
    indicators: list[Indicator],
    enrichments: dict[str, list[Enrichment]] | None = None,
    scores: dict[str, int] | None = None,
    min_size: int = 2,
) -> list[ThreatCluster]:
    """Сгруппировать индикаторы в кластеры по общим тегам, источнику и IP-резолюции.

    Рёбра графа возникают, когда два индикатора делят: редкий тег, источник-кампанию
    или (домен и IP) одну A-запись из обогащения 'resolution'.
    """
    enrichments = enrichments or {}
    scores = scores or {}
    values = [ind.value for ind in indicators]
    uf = _UnionFind(values)
    reasons: dict[frozenset[str], set[str]] = defaultdict(set)

    # Индекс: общий признак -> список индикаторов с этим признаком
    by_tag: dict[str, list[str]] = defaultdict(list)
    by_resolution: dict[str, list[str]] = defaultdict(list)
    for ind in indicators:
        for tag in ind.tags:
            by_tag[tag].append(ind.value)
        for enr in enrichments.get(ind.value, []):
            if enr.provider == "resolution":
                for ip in enr.data.get("ips", []):
                    by_resolution[ip].append(ind.value)

    def link_group(members: list[str], reason: str) -> None:
        for other in members[1:]:
            uf.union(members[0], other)
        for m in members:
            for n in members:
                if m != n:
                    reasons[frozenset((m, n))].add(reason)

    for tag, members in by_tag.items():
        if len(members) >= 2:
            link_group(members, f"общий тег '{tag}'")
    for ip, members in by_resolution.items():
        if len(members) >= 2:
            link_group(members, f"общий IP {ip}")

    # Собираем компоненты связности
    groups: dict[str, list[str]] = defaultdict(list)
    for value in values:
        groups[uf.find(value)].append(value)

    clusters: list[ThreatCluster] = []
    cid = 0
    for members in groups.values():
        if len(members) < min_size:
            continue
        cluster_reasons: set[str] = set()
        for pair, rs in reasons.items():
            if pair <= set(members):
                cluster_reasons |= rs
        cluster = ThreatCluster(
            id=cid,
            indicators=sorted(members),
            reasons=cluster_reasons,
            score=max((scores.get(m, 0) for m in members), default=0),
        )
        clusters.append(cluster)
        cid += 1
    clusters.sort(key=lambda c: c.score, reverse=True)
    for new_id, cluster in enumerate(clusters):
        cluster.id = new_id
    return clusters
