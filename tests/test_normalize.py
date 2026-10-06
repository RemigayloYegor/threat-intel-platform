import pytest

from tip.models import IndicatorType
from tip.normalize import (
    NormalizationError,
    dedup,
    detect_type,
    extract_iocs,
    make_indicator,
    normalize_value,
    refang,
)


@pytest.mark.parametrize("value,expected", [
    ("1.2.3.4", IndicatorType.IP),
    ("2001:db8::1", IndicatorType.IP),
    ("evil.example.com", IndicatorType.DOMAIN),
    ("http://evil.com/x", IndicatorType.URL),
    ("user@evil.com", IndicatorType.EMAIL),
    ("44d88612fea8a8f36de82e1278abb02f", IndicatorType.MD5),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IndicatorType.SHA1),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IndicatorType.SHA256),
])
def test_detect_type(value, expected):
    assert detect_type(value) == expected


@pytest.mark.parametrize("value", ["", "   ", "not an ioc", "12345", "...", "@@@"])
def test_detect_type_unknown(value):
    assert detect_type(value) is None


def test_refang():
    assert refang("hxxp://1[.]2[.]3[.]4") == "http://1.2.3.4"
    assert refang("evil[dot]com") == "evil.com"
    assert refang("user[at]evil[.]com") == "user@evil.com"


def test_make_indicator_refangs_and_normalizes():
    ind = make_indicator("hxxp://Evil[.]COM/Path", source="feed")
    assert ind.type == IndicatorType.URL
    assert ind.value == "http://evil.com/Path"
    assert ind.source == "feed"


def test_make_indicator_lowercases_domain_and_hash():
    assert make_indicator("EVIL.COM", "f").value == "evil.com"
    assert make_indicator("ABCDEF0123456789ABCDEF0123456789", "f").value == (
        "abcdef0123456789abcdef0123456789")


def test_make_indicator_clamps_confidence():
    assert make_indicator("1.2.3.4", "f", confidence=500).confidence == 100
    assert make_indicator("1.2.3.4", "f", confidence=-5).confidence == 0


def test_make_indicator_rejects_garbage():
    with pytest.raises(NormalizationError):
        make_indicator("just some text", "f")


def test_normalize_ipv6_compresses():
    assert normalize_value("2001:0db8:0000::1", IndicatorType.IP) == "2001:db8::1"


def test_dedup_merges_metadata():
    a = make_indicator("1.2.3.4", "feed-a", confidence=40, tags={"scan"})
    b = make_indicator("1.2.3.4", "feed-b", confidence=70, tags={"c2"})
    merged = dedup([a, b])
    assert len(merged) == 1
    m = merged[0]
    assert m.confidence == 70
    assert m.tags == {"scan", "c2"}
    assert set(m.source.split(",")) == {"feed-a", "feed-b"}


def test_extract_iocs_from_text():
    text = "connect to 185.220.101.7 and evil-c2.example, hash 44d88612fea8a8f36de82e1278abb02f"
    found = dict(extract_iocs(text))
    assert found["185.220.101.7"] == IndicatorType.IP
    assert found["evil-c2.example"] == IndicatorType.DOMAIN
    assert found["44d88612fea8a8f36de82e1278abb02f"] == IndicatorType.MD5


def test_extract_iocs_handles_defanged():
    assert ("1.2.3.4", IndicatorType.IP) in extract_iocs("beacon to 1[.]2[.]3[.]4 now")
