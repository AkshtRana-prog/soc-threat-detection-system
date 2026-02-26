import difflib

BRANDS = ["paypal", "facebook", "instagram", "amazon", "microsoft", "google"]

# =====================================================
# 🔍 PHISHING DETECTION
# =====================================================

def detect_phishing(features):
    score = 0
    reasons = []

    domain = features.get("domain", "").lower()
    domain_name = domain.split(".")[0]

    # ---- Exact Brand Impersonation ----
    for brand in BRANDS:
        if brand in domain:
            if not (domain == f"{brand}.com" or domain.endswith(f".{brand}.com")):
                reasons.append(f"Brand impersonation detected: {brand}")
                return "PHISHING", reasons, "HIGH"

    # ---- Typosquatting ----
    for brand in BRANDS:
        similarity = difflib.SequenceMatcher(None, domain_name, brand).ratio()
        if similarity > 0.8 and domain_name != brand:
            reasons.append(f"Typosquatting detected (similar to {brand})")
            return "PHISHING", reasons, "HIGH"

    # ---- Feature Scoring ----
    rules = {
        "has_ip": ("IP address used instead of domain", 5),
        "has_punycode": ("Punycode detected", 5),
        "has_at_symbol": ("Contains '@' symbol", 3),
        "shortened_url": ("Shortened URL detected", 3),
        "suspicious_subdomain": ("Suspicious subdomain detected", 3),
        "redirect_pattern": ("Redirect pattern detected", 3),
        "has_hyphen": ("Hyphen used in domain", 2),
        "has_numbers_in_domain": ("Numbers used in domain", 2),
        "long_subdomain": ("Long subdomain detected", 2),
    }

    for key, (message, weight) in rules.items():
        if features.get(key):
            score += weight
            reasons.append(message)

    if score >= 6:
        return "PHISHING", reasons, "HIGH"
    elif score >= 3:
        return "SUSPICIOUS", reasons, "MEDIUM"
    elif score >= 1:
        return "LOW RISK", reasons, "LOW"
    else:
        return "LEGITIMATE", reasons, "LOW"


# =====================================================
# 🔐 BRUTE FORCE DETECTION
# =====================================================

def detect_bruteforce(events, threshold=3):
    ip_counter = {}
    alerts = []

    for event in events:
        if event.get("failed_login") and event.get("ip"):
            ip = event["ip"]
            ip_counter[ip] = ip_counter.get(ip, 0) + 1

    for ip, count in ip_counter.items():
        if count >= threshold:
            alerts.append(
                f"Brute-force attack suspected from IP: {ip} ({count} failed attempts)"
            )

    return alerts


# =====================================================
# 🔥 CORRELATION (SEQUENCE BASED)
# =====================================================

def detect_bruteforce_success(events, threshold=3):
    ip_failures = {}
    alerts = []

    for event in events:
        ip = event.get("ip")
        if not ip:
            continue

        if event.get("failed_login"):
            ip_failures[ip] = ip_failures.get(ip, 0) + 1

        if event.get("successful_login"):
            if ip_failures.get(ip, 0) >= threshold:
                alerts.append(
                    f"CRITICAL: IP {ip} had {ip_failures[ip]} failed logins followed by SUCCESSFUL login"
                )
                ip_failures[ip] = 0  # reset after detection

    return alerts