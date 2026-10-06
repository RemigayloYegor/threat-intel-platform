import json
import threading
from datetime import datetime, timezone
from http.client import HTTPConnection

import pytest

from tip.api import create_server
from tip.models import Score, Severity
from tip.normalize import make_indicator
from tip.storage import Storage

NOW = datetime(2026, 10, 6, tzinfo=timezone.utc)


@pytest.fixture
def client():
    store = Storage(":memory:")
    store.upsert_indicators([
        make_indicator("45.155.205.99", "feed", confidence=80, tags={"c2"}, seen=NOW),
        make_indicator("evil.example", "feed", tags={"phishing"}, seen=NOW),
    ])
    store.save_score(Score("45.155.205.99", 75, Severity.HIGH, ["r"]))
    server = create_server(store, host="127.0.0.1", port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    conn = HTTPConnection("127.0.0.1", port)
    yield conn
    conn.close()
    server.shutdown()
    server.server_close()
    store.close()


def get(conn, path):
    conn.request("GET", path)
    resp = conn.getresponse()
    return resp.status, json.loads(resp.read())


def post(conn, path, body):
    payload = json.dumps(body).encode()
    conn.request("POST", path, payload, {"Content-Type": "application/json"})
    resp = conn.getresponse()
    return resp.status, json.loads(resp.read())


def test_health(client):
    assert get(client, "/health") == (200, {"status": "ok"})


def test_stats(client):
    status, data = get(client, "/stats")
    assert status == 200 and data["indicators"] == 2


def test_search_by_type(client):
    status, data = get(client, "/indicators?type=ip")
    assert status == 200
    assert [r["value"] for r in data["results"]] == ["45.155.205.99"]


def test_search_min_score(client):
    _, data = get(client, "/indicators?min_score=50")
    assert len(data["results"]) == 1


def test_search_bad_type(client):
    status, data = get(client, "/indicators?type=bogus")
    assert status == 400


def test_get_one_with_score(client):
    status, data = get(client, "/indicators/45.155.205.99")
    assert status == 200
    assert data["severity"] == "high" and data["score"] == 75


def test_get_one_not_found(client):
    status, _ = get(client, "/indicators/1.1.1.1")
    assert status == 404


def test_match_endpoint(client):
    status, data = post(client, "/match", {"text": "beacon to 45.155.205.99 now"})
    assert status == 200
    assert data["alerts"][0]["indicator"] == "45.155.205.99"


def test_match_requires_text(client):
    status, _ = post(client, "/match", {})
    assert status == 400


def test_unknown_route(client):
    assert get(client, "/nope")[0] == 404
