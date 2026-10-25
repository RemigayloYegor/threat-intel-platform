from pathlib import Path

from tip.feeds import FEED_FORMATS, FeodoTrackerFeed
from tip.models import IndicatorType

SAMPLE = Path(__file__).parent / "fixtures" / "feodo_sample.csv"


def load():
    return {i.value: i for i in FeodoTrackerFeed().load_file(SAMPLE)}


def test_parses_all_entries():
    inds = load()
    assert len(inds) == 5
    assert all(i.type == IndicatorType.IP for i in inds.values())


def test_registered_in_formats():
    assert FEED_FORMATS["feodo"] is FeodoTrackerFeed


def test_tags_include_malware_and_status():
    inds = load()
    emotet = inds["162.243.103.246"]
    assert "emotet" in emotet.tags
    assert "c2-offline" in emotet.tags
    assert {"c2", "botnet"} <= emotet.tags


def test_online_c2_higher_confidence():
    inds = load()
    online = inds["50.16.16.211"]  # QakBot, online
    offline = inds["34.204.119.63"]  # QakBot, offline
    assert online.confidence == 90
    assert offline.confidence == 60
    assert "c2-online" in online.tags
    assert "qakbot" in online.tags


def test_port_tag():
    assert "port-8080" in load()["162.243.103.246"].tags


def test_comment_and_footer_lines_skipped():
    # '# END 5 entries' и шапка не должны попадать в индикаторы
    text = SAMPLE.read_text(encoding="utf-8")
    assert "# END" in text
    assert len(FeodoTrackerFeed().load_text(text)) == 5


def test_empty_input():
    assert FeodoTrackerFeed().load_text("# only comments\n") == []
