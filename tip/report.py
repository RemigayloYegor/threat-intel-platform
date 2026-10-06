"""Генерация аналитического отчёта по данным платформы (Markdown)."""

from __future__ import annotations

from tip.models import ThreatCluster
from tip.storage import Storage

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    out += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return out + [""] if rows else out + ["| — |" * 0, "_нет данных_", ""]


def render_report(storage: Storage, clusters: list[ThreatCluster] | None = None,
                  top: int = 15) -> str:
    """Собрать Markdown-отчёт по индикаторам, кластерам и алертам."""
    stats = storage.stats()
    lines = [
        "# Отчёт Threat Intelligence",
        "",
        f"- Индикаторов: **{stats['indicators']}**",
        f"- Обогащений: {stats['enrichments']}",
        f"- Оценок риска: {stats['scores']}",
        f"- Алертов матчинга: {stats['alerts']}",
        "",
        "## Распределение по типам",
        "",
    ]
    lines += _table(["Тип", "Кол-во"],
                    sorted(stats["by_type"].items(), key=lambda x: -x[1]))

    lines += ["## Распределение по критичности", ""]
    sev_rows = [[s, stats["by_severity"].get(s, 0)] for s in _SEVERITY_ORDER
                if stats["by_severity"].get(s)]
    lines += _table(["Критичность", "Кол-во"], sev_rows)

    lines += [f"## Топ индикаторов (до {top})", ""]
    top_rows = [
        [r["value"], r["type"], r.get("score", 0), r.get("severity") or "—",
         ", ".join(sorted(filter(None, r["tags"].split(",")))) or "—"]
        for r in storage.search(min_score=0, limit=top)
    ]
    lines += _table(["Индикатор", "Тип", "Балл", "Критичность", "Теги"], top_rows)

    if clusters:
        lines += ["## Кластеры угроз", ""]
        cl_rows = [
            [c.id, len(c.indicators), c.score, "; ".join(sorted(c.reasons)) or "—"]
            for c in clusters
        ]
        lines += _table(["ID", "Индикаторов", "Макс. балл", "Причины связи"], cl_rows)

    recent = storage.recent_alerts(limit=10)
    if recent:
        lines += ["## Последние алерты", ""]
        lines += _table(
            ["Время", "Индикатор", "Тип", "Критичность", "Источник"],
            [[a["ts"], a["value"], a["type"], a["severity"], a["source"]] for a in recent],
        )
    return "\n".join(lines)
