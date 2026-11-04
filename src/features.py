"""Feature extraction for phishing email detection."""
import re
import tldextract
import numpy as np

URGENCY_WORDS = ["urgent", "verify", "suspended", "click here", "immediately", "act now",
                 "confirm", "password", "account locked", "limited time", "winner"]

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club"}


def extract_urls(text):
    return re.findall(r'https?://[^\s<>"]+', text)


def url_features(urls):
    if not urls:
        return {"num_urls": 0, "suspicious_tld": 0, "max_url_len": 0, "has_ip_url": 0}
    suspicious = 0
    max_len = 0
    has_ip = 0
    for u in urls:
        max_len = max(max_len, len(u))
        ext = tldextract.extract(u)
        tld = "." + ext.suffix if ext.suffix else ""
        if tld in SUSPICIOUS_TLDS:
            suspicious += 1
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u):
            has_ip = 1
    return {
        "num_urls": len(urls),
        "suspicious_tld": suspicious,
        "max_url_len": max_len,
        "has_ip_url": has_ip,
    }


def text_features(text):
    lower = text.lower()
    urgency = sum(1 for w in URGENCY_WORDS if w in lower)
    return {
        "urgency_count": urgency,
        "num_exclamations": text.count("!"),
        "num_caps_words": sum(1 for w in text.split() if w.isupper() and len(w) > 2),
        "length": len(text),
    }


def sender_features(sender, body):
    # mismatch between sender domain and mentioned brand
    m = re.search(r'@([\w.-]+)', sender or "")
    domain = m.group(1) if m else ""
    brands = ["paypal", "amazon", "microsoft", "apple", "google", "bank"]
    mismatch = 0
    for b in brands:
        if b in (body or "").lower() and b not in domain.lower():
            mismatch = 1
    return {"sender_domain_mismatch": mismatch, "sender_has_numbers": int(bool(re.search(r'\d', domain)))}


def extract_all(subject, body, sender):
    feats = {}
    feats.update(text_features((subject or "") + " " + (body or "")))
    feats.update(url_features(extract_urls(body or "")))
    feats.update(sender_features(sender, body))
    return feats