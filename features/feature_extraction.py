import re
from urllib.parse import urlparse


def extract_features(text):
    features = {}

    parsed = urlparse(text)
    domain = parsed.netloc if parsed.netloc else text

    features["domain"] = domain.lower()
    features["has_ip"] = bool(re.search(r"\d+\.\d+\.\d+\.\d+", domain))
    features["has_hyphen"] = "-" in domain
    features["has_numbers_in_domain"] = any(char.isdigit() for char in domain)
    features["has_at_symbol"] = "@" in text
    features["num_dots"] = domain.count(".")
    features["long_subdomain"] = features["num_dots"] > 3
    features["has_punycode"] = "xn--" in domain
    features["redirect_pattern"] = "//" in text[8:]
    features["shortened_url"] = any(short in domain for short in [
        "bit.ly", "tinyurl", "t.co", "goo.gl"
    ])
    features["suspicious_subdomain"] = domain.count(".") > 2

    return features
