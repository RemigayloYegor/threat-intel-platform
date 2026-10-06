"""CLI платформы: ingest / enrich / score / correlate / match / report / stats / serve / demo."""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from tip.correlation import correlate
from tip.feeds import FEED_FORMATS
from tip.matcher import IocMatcher
from tip.normalize import dedup
from tip.pipeline import build_demo_enrichers, enrich_and_score
from tip.report import render_report
from tip.scoring import ScoringEngine
from tip.storage import Storage


def _storage(args: argparse.Namespace) -> Storage:
    return Storage(args.db)


def cmd_ingest(args: argparse.Namespace) -> int:
    src = Path(args.file)
    if not src.is_file():
        print(f"ошибка: файл не найден: {src}", file=sys.stderr)
        return 1
    if args.format not in FEED_FORMATS:
        print(f"ошибка: неизвестный формат {args.format}", file=sys.stderr)
        return 1
    feed = FEED_FORMATS[args.format](name=args.source or args.format)
    indicators = dedup(feed.load_file(src))
    storage = _storage(args)
    n = storage.upsert_indicators(indicators)
    storage.close()
    print(f"загружено индикаторов: {n} из {src.name}")
    return 0


def cmd_enrich(args: argparse.Namespace) -> int:
    storage = _storage(args)
    n_enrich, n_score = enrich_and_score(storage, build_demo_enrichers(), ScoringEngine())
    storage.close()
    print(f"обогащений: {n_enrich}, оценок: {n_score}")
    return 0


def cmd_correlate(args: argparse.Namespace) -> int:
    storage = _storage(args)
    indicators = storage.all_indicators()
    scores = {i.value: (s.score if (s := storage.get_score(i.value)) else 0)
              for i in indicators}
    clusters = correlate(indicators, scores=scores)
    storage.close()
    print(f"найдено кластеров: {len(clusters)}")
    for c in clusters:
        print(f"  [{c.id}] индикаторов: {len(c.indicators)}, балл: {c.score}, "
              f"причины: {'; '.join(sorted(c.reasons)) or '—'}")
    return 0


def cmd_match(args: argparse.Namespace) -> int:
    src = Path(args.logfile)
    if not src.is_file():
        print(f"ошибка: файл не найден: {src}", file=sys.stderr)
        return 1
    storage = _storage(args)
    matcher = IocMatcher.from_storage(storage)
    alerts = list(matcher.scan_lines(src.read_text(encoding="utf-8").splitlines()))
    n = storage.save_alerts(alerts)
    storage.close()
    print(f"совпадений с IOC: {n}")
    for a in alerts:
        print(f"  [{a.severity.value.upper()}] {a.indicator} ({a.indicator_type.value}) "
              f"<- {a.source}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    storage = _storage(args)
    indicators = storage.all_indicators()
    scores = {i.value: (s.score if (s := storage.get_score(i.value)) else 0)
              for i in indicators}
    clusters = correlate(indicators, scores=scores)
    md = render_report(storage, clusters, top=args.top)
    storage.close()
    if args.output:
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"отчёт сохранён: {args.output}")
    else:
        print(md)
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    storage = _storage(args)
    stats = storage.stats()
    storage.close()
    print(f"индикаторов: {stats['indicators']}")
    print(f"обогащений: {stats['enrichments']}, оценок: {stats['scores']}, "
          f"алертов: {stats['alerts']}")
    print("по типам:", stats["by_type"])
    print("по критичности:", stats["by_severity"])
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from tip.api import create_server

    storage = _storage(args)
    server = create_server(storage, host=args.host, port=args.port)
    print(f"API на http://{args.host}:{args.port} (Ctrl+C для остановки)", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        storage.close()
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from tip import generator

    work = Path(args.workdir or tempfile.mkdtemp(prefix="tip-demo-"))
    feeds = generator.write_demo_feeds(work)
    log = generator.write_demo_log(work / "events.log")

    storage = _storage(args)
    total = 0
    for fmt, path in feeds.items():
        feed = FEED_FORMATS[fmt](name=f"demo-{fmt}")
        total += storage.upsert_indicators(dedup(feed.load_file(path)))
    n_enrich, n_score = enrich_and_score(storage, build_demo_enrichers(), ScoringEngine())
    matcher = IocMatcher.from_storage(storage)
    alerts = list(matcher.scan_lines(log.read_text(encoding="utf-8").splitlines()))
    storage.save_alerts(alerts)
    indicators = storage.all_indicators()
    scores = {i.value: (s.score if (s := storage.get_score(i.value)) else 0)
              for i in indicators}
    clusters = correlate(indicators, scores=scores)

    print(f"демо-данные: {work}")
    print(f"индикаторов: {total}, обогащений: {n_enrich}, оценок: {n_score}")
    print(f"алертов матчинга: {len(alerts)}, кластеров: {len(clusters)}")
    if args.output:
        Path(args.output).write_text(render_report(storage, clusters), encoding="utf-8")
        print(f"отчёт: {args.output}")
    storage.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Собрать парсер аргументов CLI."""
    p = argparse.ArgumentParser(prog="tip", description="Threat Intelligence Platform")
    p.add_argument("--db", default="tip.db", help="путь к базе SQLite (по умолчанию tip.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    ing = sub.add_parser("ingest", help="загрузить индикаторы из фида")
    ing.add_argument("file")
    ing.add_argument("-f", "--format", choices=sorted(FEED_FORMATS), required=True)
    ing.add_argument("--source", help="имя источника (по умолчанию = формат)")
    ing.set_defaults(func=cmd_ingest)

    sub.add_parser("enrich", help="обогатить и оценить индикаторы").set_defaults(func=cmd_enrich)
    sub.add_parser("correlate", help="сгруппировать в кластеры").set_defaults(func=cmd_correlate)
    sub.add_parser("stats", help="статистика базы").set_defaults(func=cmd_stats)

    mt = sub.add_parser("match", help="сопоставить лог с базой IOC")
    mt.add_argument("logfile")
    mt.set_defaults(func=cmd_match)

    rp = sub.add_parser("report", help="аналитический отчёт (Markdown)")
    rp.add_argument("-o", "--output")
    rp.add_argument("--top", type=int, default=15)
    rp.set_defaults(func=cmd_report)

    sv = sub.add_parser("serve", help="запустить REST API")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.set_defaults(func=cmd_serve)

    dm = sub.add_parser("demo", help="сквозной прогон на синтетических данных")
    dm.add_argument("--workdir", help="куда положить демо-фиды и лог")
    dm.add_argument("-o", "--output", help="сохранить отчёт в файл")
    dm.set_defaults(func=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    """Точка входа CLI."""
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
