"""REST API платформы на стандартной библиотеке (http.server)."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from tip.matcher import IocMatcher
from tip.models import IndicatorType
from tip.storage import Storage


class _Handler(BaseHTTPRequestHandler):
    """Маршрутизация запросов к хранилищу."""

    def log_message(self, *args) -> None:  # noqa: D102 - глушим логи в stderr
        pass

    @property
    def store(self) -> Storage:
        return self.server.storage  # type: ignore[attr-defined]

    def _send(self, code: int, payload: object) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            return {}

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        query = parse_qs(parsed.query)
        if parts == ["health"]:
            return self._send(200, {"status": "ok"})
        if parts == ["stats"]:
            return self._send(200, self.store.stats())
        if parts == ["indicators"]:
            return self._handle_search(query)
        if len(parts) == 2 and parts[0] == "indicators":
            return self._handle_get_one(parts[1])
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parts = [p for p in urlparse(self.path).path.split("/") if p]
        body = self._read_json()
        if parts == ["match"]:
            return self._handle_match(body)
        self._send(404, {"error": "not found"})

    def _handle_search(self, query: dict) -> None:
        itype = None
        if "type" in query:
            try:
                itype = IndicatorType(query["type"][0])
            except ValueError:
                return self._send(400, {"error": "unknown type"})
        tag = query.get("tag", [None])[0]
        try:
            min_score = int(query.get("min_score", ["0"])[0])
            limit = int(query.get("limit", ["100"])[0])
        except ValueError:
            return self._send(400, {"error": "min_score/limit must be int"})
        self._send(200, {"results": self.store.search(itype, tag, min_score, limit)})

    def _handle_get_one(self, value: str) -> None:
        ind = self.store.get_indicator(value)
        if ind is None:
            return self._send(404, {"error": "indicator not found"})
        score = self.store.get_score(value)
        self._send(200, {
            "value": ind.value, "type": ind.type.value, "source": ind.source,
            "confidence": ind.confidence, "tags": sorted(ind.tags),
            "first_seen": ind.first_seen.isoformat(), "last_seen": ind.last_seen.isoformat(),
            "score": score.score if score else None,
            "severity": score.severity.value if score else None,
            "enrichments": [{"provider": e.provider, "data": e.data}
                            for e in self.store.get_enrichments(value)],
        })

    def _handle_match(self, body: dict) -> None:
        text = body.get("text", "")
        if not isinstance(text, str) or not text:
            return self._send(400, {"error": "field 'text' required"})
        matcher = IocMatcher.from_storage(self.store)
        alerts = matcher.match_text(text, sensor=body.get("sensor", "api"))
        self._send(200, {"alerts": [
            {"indicator": a.indicator, "type": a.indicator_type.value,
             "severity": a.severity.value, "source": a.source} for a in alerts]})


def create_server(storage: Storage, host: str = "127.0.0.1", port: int = 8000):
    """Создать HTTP-сервер поверх хранилища."""
    # Один поток обслуживания: запросы сериализуются, доступ к SQLite безопасен
    server = HTTPServer((host, port), _Handler)
    server.storage = storage  # type: ignore[attr-defined]
    return server
