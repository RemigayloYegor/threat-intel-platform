"""Хранилище индикаторов, обогащений, оценок и алертов на SQLite."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from datetime import datetime

from tip.models import (
    Alert,
    Enrichment,
    Indicator,
    IndicatorType,
    Score,
    Severity,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    value TEXT NOT NULL,
    type TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    tags TEXT NOT NULL,
    raw TEXT,
    PRIMARY KEY (type, value)
);
CREATE INDEX IF NOT EXISTS idx_ind_value ON indicators (value);
CREATE TABLE IF NOT EXISTS enrichments (
    value TEXT NOT NULL, provider TEXT NOT NULL, data TEXT NOT NULL, ts TEXT NOT NULL,
    PRIMARY KEY (value, provider)
);
CREATE TABLE IF NOT EXISTS scores (
    value TEXT PRIMARY KEY, score INTEGER NOT NULL, severity TEXT NOT NULL, reasons TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    ts TEXT NOT NULL, value TEXT NOT NULL, type TEXT NOT NULL, severity TEXT NOT NULL,
    source TEXT NOT NULL, context TEXT NOT NULL
);
"""


class Storage:
    """Доступ к базе Threat Intelligence."""

    def __init__(self, path: str = ":memory:") -> None:
        # check_same_thread=False: соединение используется HTTP-сервером из другого потока
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        """Закрыть соединение."""
        self.conn.close()

    # --- индикаторы ---
    def upsert_indicators(self, indicators: Iterable[Indicator]) -> int:
        """Вставить или обновить индикаторы, объединяя метаданные с существующими."""
        count = 0
        for ind in indicators:
            existing = self.get_indicator(ind.value)
            if existing is not None:
                existing.merge(ind)
                ind = existing
            self.conn.execute(
                """INSERT INTO indicators (value, type, source, first_seen, last_seen,
                   confidence, tags, raw) VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(type, value) DO UPDATE SET source=excluded.source,
                   first_seen=excluded.first_seen, last_seen=excluded.last_seen,
                   confidence=excluded.confidence, tags=excluded.tags""",
                (ind.value, ind.type.value, ind.source, ind.first_seen.isoformat(),
                 ind.last_seen.isoformat(), ind.confidence,
                 ",".join(sorted(ind.tags)), ind.raw),
            )
            count += 1
        self.conn.commit()
        return count

    def get_indicator(self, value: str) -> Indicator | None:
        """Получить индикатор по значению."""
        row = self.conn.execute(
            "SELECT * FROM indicators WHERE value = ?", (value,)
        ).fetchone()
        return _row_to_indicator(row) if row else None

    def all_indicators(self) -> list[Indicator]:
        """Вернуть все индикаторы."""
        return [_row_to_indicator(r) for r in self.conn.execute("SELECT * FROM indicators")]

    def search(self, itype: IndicatorType | None = None, tag: str | None = None,
               min_score: int = 0, limit: int = 100) -> list[dict]:
        """Поиск индикаторов с фильтрами по типу, тегу и минимальному баллу."""
        sql = ["SELECT i.*, COALESCE(s.score,0) AS score, s.severity FROM indicators i",
               "LEFT JOIN scores s ON s.value = i.value WHERE 1=1"]
        params: list = []
        if itype is not None:
            sql.append("AND i.type = ?")
            params.append(itype.value)
        if tag is not None:
            sql.append("AND (',' || i.tags || ',') LIKE ?")
            params.append(f"%,{tag},%")
        if min_score > 0:
            sql.append("AND COALESCE(s.score,0) >= ?")
            params.append(min_score)
        sql.append("ORDER BY score DESC, i.value LIMIT ?")
        params.append(limit)
        return [dict(r) for r in self.conn.execute(" ".join(sql), params)]

    # --- обогащения ---
    def save_enrichment(self, enrichment: Enrichment) -> None:
        """Сохранить обогащение (перезаписывает запись того же провайдера)."""
        self.conn.execute(
            """INSERT INTO enrichments (value, provider, data, ts) VALUES (?,?,?,?)
               ON CONFLICT(value, provider) DO UPDATE SET data=excluded.data, ts=excluded.ts""",
            (enrichment.indicator, enrichment.provider,
             json.dumps(enrichment.data, ensure_ascii=False), enrichment.ts.isoformat()),
        )
        self.conn.commit()

    def get_enrichments(self, value: str) -> list[Enrichment]:
        """Получить все обогащения индикатора."""
        rows = self.conn.execute("SELECT * FROM enrichments WHERE value = ?", (value,))
        return [
            Enrichment(r["value"], r["provider"], json.loads(r["data"]),
                       datetime.fromisoformat(r["ts"]))
            for r in rows
        ]

    # --- оценки ---
    def save_score(self, score: Score) -> None:
        """Сохранить оценку риска индикатора."""
        self.conn.execute(
            """INSERT INTO scores (value, score, severity, reasons) VALUES (?,?,?,?)
               ON CONFLICT(value) DO UPDATE SET score=excluded.score,
               severity=excluded.severity, reasons=excluded.reasons""",
            (score.indicator, score.score, score.severity.value,
             json.dumps(score.reasons, ensure_ascii=False)),
        )
        self.conn.commit()

    def get_score(self, value: str) -> Score | None:
        """Получить оценку индикатора."""
        row = self.conn.execute("SELECT * FROM scores WHERE value = ?", (value,)).fetchone()
        if not row:
            return None
        return Score(row["value"], row["score"], Severity(row["severity"]),
                     json.loads(row["reasons"]))

    # --- алерты ---
    def save_alerts(self, alerts: Iterable[Alert]) -> int:
        """Сохранить алерты матчинга."""
        rows = [(a.ts.isoformat(), a.indicator, a.indicator_type.value, a.severity.value,
                 a.source, a.context) for a in alerts]
        self.conn.executemany(
            "INSERT INTO alerts (ts, value, type, severity, source, context) VALUES (?,?,?,?,?,?)",
            rows,
        )
        self.conn.commit()
        return len(rows)

    def recent_alerts(self, limit: int = 50) -> list[dict]:
        """Последние алерты."""
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,))]

    # --- статистика ---
    def stats(self) -> dict:
        """Сводная статистика базы."""
        def scalar(sql: str) -> int:
            return self.conn.execute(sql).fetchone()[0]

        by_type = {r["type"]: r["n"] for r in self.conn.execute(
            "SELECT type, COUNT(*) AS n FROM indicators GROUP BY type")}
        by_sev = {r["severity"]: r["n"] for r in self.conn.execute(
            "SELECT severity, COUNT(*) AS n FROM scores GROUP BY severity")}
        return {
            "indicators": scalar("SELECT COUNT(*) FROM indicators"),
            "enrichments": scalar("SELECT COUNT(*) FROM enrichments"),
            "scores": scalar("SELECT COUNT(*) FROM scores"),
            "alerts": scalar("SELECT COUNT(*) FROM alerts"),
            "by_type": by_type,
            "by_severity": by_sev,
        }


def _row_to_indicator(row: sqlite3.Row) -> Indicator:
    return Indicator(
        value=row["value"],
        type=IndicatorType(row["type"]),
        source=row["source"],
        first_seen=datetime.fromisoformat(row["first_seen"]),
        last_seen=datetime.fromisoformat(row["last_seen"]),
        confidence=row["confidence"],
        tags=set(filter(None, row["tags"].split(","))),
        raw=row["raw"] or "",
    )
