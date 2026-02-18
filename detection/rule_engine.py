BRANDS = ["paypal", "facebook", "instagram", "amazon", "microsoft", "google"]

def check_phishing(features):
    score = 0
    reasons = []

    domain = features.get("domain", "").lower()

    # Brand impersonation
    for brand in BRANDS:
        if brand in domain:
            if not (domain == f"{brand}.com" or domain.endswith(f".{brand}.com")):
                reasons.append(f"Brand impersonation detected: {brand}")
                return "PHISHING", reasons, "HIGH"

    # Typosquatting
    if features.get("possible_typosquat"):
        reasons.append("Brand impersonation detected (typosquatting attack)")
        return "PHISHING", reasons, "HIGH"

    if features.get("has_ip"):
        score += 5
        reasons.append("IP address used instead of domain")

    if features.get("has_punycode"):
        score += 5
        reasons.append("Punycode detected")

    if features.get("has_at_symbol"):
        score += 3
        reasons.append("Contains '@' symbol")

    if features.get("shortened_url"):
        score += 3
        reasons.append("Shortened URL detected")

    if features.get("suspicious_subdomain"):
        score += 3
        reasons.append("Suspicious subdomain detected")

    if features.get("redirect_pattern"):
        score += 3
        reasons.append("Redirect pattern detected")

    if features.get("has_hyphen"):
        score += 1
        reasons.append("Hyphen used in domain")

    if features.get("has_numbers_in_domain"):
        score += 1
        reasons.append("Numbers used in domain")

    if features.get("long_subdomain"):
        score += 1
        reasons.append("Long subdomain detected")

    if score >= 6:
        return "PHISHING", reasons, "HIGH"
    elif score >= 3:
        return "SUSPICIOUS", reasons, "MEDIUM"
    elif score >= 1:
        return "LOW RISK", reasons, "LOW"
    else:
        return "LEGITIMATE", reasons, "LOW"
