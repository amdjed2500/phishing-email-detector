"""Feature extraction for phishing email detection."""
import re
import tldextract
import numpy as np
import math
from urllib.parse import urlparse

URGENCY_WORDS = ["urgent", "verify", "suspended", "click here", "immediately", "act now",
                 "confirm", "password", "account locked", "limited time", "winner",
                 "congratulations", "selected", "prize", "lottery", "inheritance"]

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
                    ".buzz", ".work", ".date", ".racing", ".win", ".bid"}

BRAND_NAMES = ["paypal", "amazon", "microsoft", "apple", "google", "bank",
               "facebook", "instagram", "netflix", "linkedin", "dropbox",
               "outlook", "office365", "appleid", "icloud"]


def extract_urls(text):
    return re.findall(r'https?://[^\s<>"\']+', text)


def url_entropy(url):
    if not url:
        return 0.0
    freq = {}
    for c in url:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(url)
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def url_features(urls):
    if not urls:
        return {"num_urls": 0, "suspicious_tld": 0, "max_url_len": 0,
                "has_ip_url": 0, "avg_url_entropy": 0.0, "has_shortener": 0,
                "num_suspicious_paths": 0}
    suspicious = 0
    max_len = 0
    has_ip = 0
    total_entropy = 0.0
    has_shortener = 0
    suspicious_paths = 0
    shorteners = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"}
    suspicious_path_keywords = {"login", "verify", "account", "secure", "update", "confirm", "password"}

    for u in urls:
        max_len = max(max_len, len(u))
        ext = tldextract.extract(u)
        tld = "." + ext.suffix if ext.suffix else ""
        if tld in SUSPICIOUS_TLDS:
            suspicious += 1
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u):
            has_ip = 1
        total_entropy += url_entropy(u)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        if domain.lower() in shorteners:
            has_shortener = 1
        path = urlparse(u).path.lower()
        if any(kw in path for kw in suspicious_path_keywords):
            suspicious_paths += 1

    return {
        "num_urls": len(urls),
        "suspicious_tld": suspicious,
        "max_url_len": max_len,
        "has_ip_url": has_ip,
        "avg_url_entropy": round(total_entropy / len(urls), 3),
        "has_shortener": has_shortener,
        "num_suspicious_paths": suspicious_paths,
    }


def text_features(text):
    lower = text.lower()
    urgency = sum(1 for w in URGENCY_WORDS if w in lower)
    return {
        "urgency_count": urgency,
        "num_exclamations": text.count("!"),
        "num_caps_words": sum(1 for w in text.split() if w.isupper() and len(w) > 2),
        "length": len(text),
        "num_question_marks": text.count("?"),
        "has_html": int(bool(re.search(r'<[^>]+>', text))),
        "num_links_text": len(re.findall(r'click here|click below|click this', lower)),
    }


def sender_features(sender, body):
    m = re.search(r'@([\w.-]+)', sender or "")
    domain = m.group(1) if m else ""
    mismatch = 0
    for b in BRAND_NAMES:
        if b in (body or "").lower() and b not in domain.lower():
            mismatch = 1
    display_name_spoof = 0
    if sender:
        name_match = re.match(r'^"?([^"<]+)"?\s*<', sender)
        if name_match:
            display_name = name_match.group(1).lower()
            for b in BRAND_NAMES:
                if b in display_name and b not in domain.lower():
                    display_name_spoof = 1
    return {
        "sender_domain_mismatch": mismatch,
        "sender_has_numbers": int(bool(re.search(r'\d', domain))),
        "display_name_spoof": display_name_spoof,
        "sender_domain_length": len(domain),
    }


def header_features(headers):
    feats = {
        "spf_pass": 0, "spf_fail": 0,
        "dkim_pass": 0, "dkim_fail": 0,
        "dmarc_pass": 0, "dmarc_fail": 0,
        "has_received_spf": 0,
        "num_received": 0,
        "has_x_mailer": 0,
    }
    if not headers:
        return feats

    headers_lower = headers.lower()

    if "spf=pass" in headers_lower or "received-spf: pass" in headers_lower:
        feats["spf_pass"] = 1
    elif "spf=fail" in headers_lower or "spf=softfail" in headers_lower:
        feats["spf_fail"] = 1

    if "dkim=pass" in headers_lower:
        feats["dkim_pass"] = 1
    elif "dkim=fail" in headers_lower:
        feats["dkim_fail"] = 1

    if "dmarc=pass" in headers_lower:
        feats["dmarc_pass"] = 1
    elif "dmarc=fail" in headers_lower:
        feats["dmarc_fail"] = 1

    feats["num_received"] = headers_lower.count("received:")
    if "x-mailer" in headers_lower:
        feats["has_x_mailer"] = 1
    if "received-spf" in headers_lower:
        feats["has_received_spf"] = 1

    return feats


def extract_all(subject, body, sender, headers=None):
    feats = {}
    feats.update(text_features((subject or "") + " " + (body or "")))
    feats.update(url_features(extract_urls(body or "")))
    feats.update(sender_features(sender, body))
    feats.update(header_features(headers))
    return feats
