import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from features import extract_all, url_features, text_features


def test_url_features():
    f = url_features(["http://paypal-secure.tk/login"])
    assert f["suspicious_tld"] == 1
    assert f["num_urls"] == 1


def test_text_features():
    f = text_features("URGENT! Click here now!!!")
    assert f["urgency_count"] >= 2
    assert f["num_exclamations"] == 4


def test_extract_all():
    f = extract_all("Verify account", "Click http://x.tk", "a@b.com")
    assert "num_urls" in f
    assert "urgency_count" in f