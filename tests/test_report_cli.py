from datetime import datetime, timezone

from tip.cli import main
from tip.correlation import correlate
from tip.models import Score, Severity
from tip.normalize import make_indicator
from tip.report import render_report
from tip.storage import Storage

NOW = datetime(2026, 10, 6, tzinfo=timezone.utc)


def test_render_report_sections():
    store = Storage(":memory:")
    store.upsert_indicators([
        make_indicator("45.155.205.99", "feed", tags={"c2"}, seen=NOW),
        make_indicator("evil.example", "feed", tags={"c2"}, seen=NOW),
    ])
    store.save_score(Score("45.155.205.99", 80, Severity.CRITICAL, []))
    clusters = correlate(store.all_indicators(), scores={"45.155.205.99": 80})
    md = render_report(store, clusters)
    assert "# Отчёт Threat Intelligence" in md
    assert "Распределение по типам" in md
    assert "Кластеры угроз" in md
    assert "45.155.205.99" in md
    store.close()


def test_report_empty():
    store = Storage(":memory:")
    md = render_report(store)
    assert "Индикаторов: **0**" in md
    store.close()


def test_cli_demo_end_to_end(tmp_path, capsys):
    db = tmp_path / "tip.db"
    report = tmp_path / "report.md"
    rc = main(["--db", str(db), "demo", "--workdir", str(tmp_path), "-o", str(report)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "алертов матчинга:" in out
    text = report.read_text(encoding="utf-8")
    assert "Отчёт Threat Intelligence" in text
    # В демо-кампании домены и IP должны найтись в логе
    assert "evil-c2.example" in text or "45.155.205.99" in text


def test_cli_ingest_enrich_match_flow(tmp_path, capsys):
    db = tmp_path / "f.db"
    feed = tmp_path / "ips.txt"
    feed.write_text("45.155.205.99\n185.220.101.7\n8.8.8.8\n", encoding="utf-8")
    assert main(["--db", str(db), "ingest", str(feed), "-f", "txt"]) == 0
    assert main(["--db", str(db), "enrich"]) == 0
    log = tmp_path / "events.log"
    log.write_text("conn to 45.155.205.99:443\nclean 8.8.8.8\n", encoding="utf-8")
    assert main(["--db", str(db), "match", str(log)]) == 0
    out = capsys.readouterr().out
    assert "совпадений с IOC:" in out


def test_cli_ingest_missing_file(tmp_path, capsys):
    assert main(["--db", str(tmp_path / "x.db"), "ingest", str(tmp_path / "no.txt"),
                 "-f", "txt"]) == 1
    assert "не найден" in capsys.readouterr().err


def test_cli_stats(tmp_path, capsys):
    db = tmp_path / "s.db"
    feed = tmp_path / "d.csv"
    feed.write_text("indicator,tags\nevil.example,c2\n", encoding="utf-8")
    main(["--db", str(db), "ingest", str(feed), "-f", "csv"])
    assert main(["--db", str(db), "stats"]) == 0
    assert "индикаторов: 1" in capsys.readouterr().out
