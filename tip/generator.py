"""Генератор демонстрационных фидов и логов для сквозного прогона платформы."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

# Индикаторы одной «кампании»: общий тег c2 связывает их при корреляции
CAMPAIGN = {
    "domains": ["evil-c2.example", "payload-host.example", "phish-login.example"],
    "ips": ["185.220.101.7", "45.155.205.99", "91.240.118.20"],
    "hashes": [
        "44d88612fea8a8f36de82e1278abb02f",  # md5
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # sha1
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256
    ],
    # Даты регистрации доменов: первые два «молодые» (повышают риск)
    "young_created": {
        "evil-c2.example": datetime(2026, 9, 20, tzinfo=timezone.utc),
        "payload-host.example": datetime(2026, 9, 25, tzinfo=timezone.utc),
        "phish-login.example": datetime(2019, 1, 1, tzinfo=timezone.utc),
    },
}
_CAMPAIGN = CAMPAIGN  # обратная совместимость


def write_demo_feeds(out_dir: str | Path) -> dict[str, Path]:
    """Создать демо-фиды в форматах txt, csv, stix, misp. Вернуть пути."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}

    # TXT: IP-адреса (часть в defanged-виде)
    txt = ["# c2 infrastructure", "185[.]220[.]101[.]7", "45.155.205.99",
           "91.240.118.20", "8.8.8.8"]
    paths["txt"] = _write(out / "feed_ips.txt", "\n".join(txt))

    # CSV: домены с доверием и тегами
    csv_rows = ["indicator,confidence,tags"]
    for dom in _CAMPAIGN["domains"]:
        csv_rows.append(f"{dom},80,c2;phishing")
    csv_rows.append("good-site.example,10,benign")
    paths["csv"] = _write(out / "feed_domains.csv", "\n".join(csv_rows))

    # STIX 2.1 bundle: хеши
    objects = [
        {"type": "indicator", "labels": ["malware", "c2"], "confidence": 90,
         "pattern": f"[file:hashes.'SHA-256' = '{h}']"}
        for h in _CAMPAIGN["hashes"]
    ]
    paths["stix"] = _write(out / "feed_hashes.stix.json",
                           json.dumps({"type": "bundle", "objects": objects}, indent=2))

    # MISP/OTX: смешанный список
    misp = {"results": [
        {"indicator": "hxxp://payload-host[.]example/x.exe", "confidence": 85,
         "tags": ["malware", "c2"]},
        {"indicator": "attacker@evil-c2.example", "confidence": 60, "tags": ["phishing"]},
    ]}
    paths["misp"] = _write(out / "feed_misp.json", json.dumps(misp, indent=2))
    return paths


def write_demo_log(path: str | Path) -> Path:
    """Создать демо-лог, где часть событий содержит индикаторы из фидов."""
    lines = [
        "2026-10-06T10:00:01 proxy: GET http://good-site.example/index.html 200",
        "2026-10-06T10:01:14 dns: query evil-c2.example from 10.0.0.5",
        "2026-10-06T10:02:33 firewall: outbound 10.0.0.5 -> 185.220.101.7:443 ALLOW",
        "2026-10-06T10:03:02 proxy: GET http://payload-host.example/x.exe 200",
        "2026-10-06T10:04:51 mail: from attacker@evil-c2.example subject 'invoice'",
        "2026-10-06T10:05:10 edr: file created hash=44d88612fea8a8f36de82e1278abb02f",
        "2026-10-06T10:06:00 dns: query cdn.microsoft.com from 10.0.0.9",
    ]
    return _write(Path(path), "\n".join(lines))


def _write(path: Path, content: str) -> Path:
    path.write_text(content + "\n", encoding="utf-8")
    return path
