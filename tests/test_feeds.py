from tip.feeds import CsvFeed, MispOtxFeed, StixFeed, TextListFeed
from tip.models import IndicatorType


def test_textlist_feed_skips_comments_and_garbage():
    text = "# header\n185.220.101.7\n; note\nnot-an-ioc here\nevil.example\n"
    inds = TextListFeed(name="tl").load_text(text)
    values = {i.value for i in inds}
    assert values == {"185.220.101.7", "evil.example"}
    assert all(i.source == "tl" for i in inds)


def test_textlist_feed_refangs():
    inds = TextListFeed().load_text("1[.]2[.]3[.]4\n")
    assert inds[0].value == "1.2.3.4"


def test_csv_feed_reads_confidence_and_tags():
    text = "indicator,confidence,tags\nevil.com,80,c2;phishing\ngood.com,10,benign\n"
    feed = CsvFeed(confidence_col="confidence", tags_col="tags", name="csv")
    inds = {i.value: i for i in feed.load_text(text)}
    assert inds["evil.com"].confidence == 80
    assert inds["evil.com"].tags == {"c2", "phishing"}
    assert inds["good.com"].tags == {"benign"}


def test_csv_feed_missing_value_column():
    assert CsvFeed(value_col="ioc").load_text("other,col\na,b\n") == []


def test_csv_feed_bad_confidence_falls_back():
    feed = CsvFeed(confidence_col="confidence", confidence=42)
    inds = feed.load_text("indicator,confidence\n1.2.3.4,notanumber\n")
    assert inds[0].confidence == 42


def test_stix_feed_extracts_pattern_values():
    bundle = """{"type":"bundle","objects":[
      {"type":"indicator","labels":["malware","c2"],"confidence":90,
       "pattern":"[ipv4-addr:value = '45.155.205.99']"},
      {"type":"identity","name":"ignore me"}
    ]}"""
    inds = StixFeed().load_text(bundle)
    assert len(inds) == 1
    assert inds[0].value == "45.155.205.99"
    assert inds[0].tags == {"malware", "c2"}
    assert inds[0].confidence == 90


def test_stix_feed_invalid_json():
    assert StixFeed().load_text("{bad json") == []


def test_misp_feed_reads_results_list():
    data = """{"results":[
      {"indicator":"hxxp://evil[.]com/x","confidence":85,"tags":["malware"]},
      {"indicator":"attacker@evil.com","tags":"phishing"},
      {"indicator":""}
    ]}"""
    inds = {i.value: i for i in MispOtxFeed().load_text(data)}
    assert "http://evil.com/x" in inds
    assert inds["http://evil.com/x"].type == IndicatorType.URL
    assert inds["attacker@evil.com"].tags == {"phishing"}


def test_misp_feed_plain_list():
    inds = MispOtxFeed().load_text('[{"indicator":"1.2.3.4"}]')
    assert inds[0].value == "1.2.3.4"
