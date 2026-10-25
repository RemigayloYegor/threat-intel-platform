# threat-intel-platform

![CI](https://github.com/RemigayloYegor/threat-intel-platform/actions/workflows/ci.yml/badge.svg)

Платформа **Threat Intelligence**: сбор индикаторов компрометации (IOC) из разных фидов,
обогащение, расчёт риска, корреляция в кластеры угроз, сопоставление с событиями и REST API.
Ядро написано на чистой стандартной библиотеке Python — без внешних зависимостей.

```
 фиды (txt/csv/      нормализация      обогащение        скоринг        корреляция
 stix/misp)      ──▶ и дедупликация ──▶ (geoip/          риска     ──▶  в кластеры
      │               IOC               reputation/       0-100            угроз
      │                                 whois)              │                │
      ▼                                                     ▼                ▼
 матчинг событий ◀──────────── SQLite (indicators, enrichments, scores, alerts) ──▶ REST API
 (логи → алерты)                              │                                      отчёты (MD)
```

## Возможности

- **Форматы фидов:** построчный список, CSV, STIX 2.1 bundle, MISP/OTX JSON и реальный
  фид **abuse.ch Feodo Tracker** (C2-адреса ботнетов Emotet/QakBot, без API-ключа). Понимает
  «обезвреженные» индикаторы (`hxxp://1[.]2[.]3[.]4`).
- **Типы IOC:** IP (v4/v6), домен, URL, email, MD5/SHA1/SHA256 — с автоопределением типа.
- **Обогащение:** гео/ASN по таблице префиксов, агрегированная репутация нескольких
  провайдеров, возраст домена (молодые домены подозрительнее). Провайдеры инъектируются.
- **Скоринг риска 0–100** с объяснением вклада каждого фактора и уровнем критичности.
- **Корреляция** связанных индикаторов в кластеры (общие теги, IP-резолюция) через
  систему непересекающихся множеств.
- **Матчинг** произвольных логов по базе IOC с порогом критичности.
- **REST API** на `http.server` и генератор аналитических отчётов в Markdown.

## Быстрый старт

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

# Сквозной прогон на синтетических данных (фиды + лог генерируются сами)
tip --db tip.db demo -o report.md
```

Вывод демо:

```
индикаторов: 13, обогащений: 20, оценок: 13
алертов матчинга: 4, кластеров: 1
```

Фрагмент отчёта (`report.md`):

| Индикатор | Тип | Балл | Критичность | Теги |
|---|---|---|---|---|
| evil-c2.example | domain | 93 | critical | c2, phishing |
| payload-host.example | domain | 93 | critical | c2, phishing |
| 185.220.101.7 | ip | 74 | high | — |
| http://payload-host.example/x.exe | url | 73 | high | c2, malware |

## Отдельные команды

```powershell
tip --db tip.db ingest feed_ips.txt -f txt         # загрузка фида (txt/csv/stix/misp)
tip --db tip.db enrich                              # обогащение + скоринг
tip --db tip.db correlate                           # кластеры угроз
tip --db tip.db match events.log                    # сопоставление лога с базой IOC
tip --db tip.db report -o report.md                 # аналитический отчёт
tip --db tip.db serve --port 8000                   # REST API
```

### REST API

| Метод | Путь | Описание |
|---|---|---|
| GET | `/health` | проверка живости |
| GET | `/stats` | сводная статистика |
| GET | `/indicators?type=ip&min_score=50` | поиск индикаторов |
| GET | `/indicators/{value}` | карточка индикатора с обогащением и оценкой |
| POST | `/match` | найти IOC в тексте (`{"text": "..."}`) |

## Архитектура

| Модуль | Ответственность |
|---|---|
| [tip/normalize.py](tip/normalize.py) | распознавание, валидация, нормализация, дедуп IOC |
| [tip/feeds/](tip/feeds/) | парсеры фидов (txt, csv, stix, misp) |
| [tip/enrichment/](tip/enrichment/) | обогатители (geoip, reputation, whois) |
| [tip/scoring.py](tip/scoring.py) | движок оценки риска |
| [tip/correlation.py](tip/correlation.py) | кластеризация через union-find |
| [tip/storage.py](tip/storage.py) | хранилище SQLite |
| [tip/matcher.py](tip/matcher.py) | матчинг событий по базе IOC |
| [tip/api.py](tip/api.py) | REST API |
| [tip/report.py](tip/report.py) | генерация отчётов |

Подробнее — в [docs/architecture.md](docs/architecture.md).

## Решения и обоснование

- **Zero-dependency ядро.** Весь функционал — на стандартной библиотеке, поэтому проект
  запускается где угодно и проходит CI без установки тяжёлых пакетов.
- **Инъекция провайдеров обогащения.** `ReputationEnricher`, `DomainAgeEnricher` получают
  источники данных извне. Это делает их детерминированно тестируемыми без сети.
- **Нормализация и дедуп до хранения.** Один индикатор из разных фидов схлопывается в
  запись с объединёнными тегами, максимумом доверия и расширенным окном наблюдения.
- **Прозрачный скоринг.** Каждая оценка несёт список причин — почему балл именно такой.
- **Корреляция через union-find** даёт транзитивную группировку за почти линейное время.

## Тесты

```powershell
ruff check .
pytest -q
```

90 тестов покрывают нормализацию (включая defang и мусор), все четыре парсера фидов,
обогатители, скоринг (пороги, штрафы, ограничение 0–100), корреляцию (транзитивность,
сортировка), хранилище, матчинг, REST API (поднимается на эфемерном порту) и CLI.

## Дальнейшие шаги

- Реальные провайдеры: VirusTotal, AbuseIPDB, OTX (поверх текущих интерфейсов)
- Экспорт индикаторов в STIX/Sigma
- Веб-дашборд поверх REST API
