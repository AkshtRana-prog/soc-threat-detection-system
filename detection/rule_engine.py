import time
from collections import defaultdict
from urllib.parse import urlparse

# ==============================
# PHISHING DETECTION ENGINE
# ==============================

BRANDS = ["paypal", "facebook", "instagram", "amazon", "microsoft", "google"]


def check_phishing(features):
    score = 0
    reasons = []

    domain = features.get("domain", "").lower()

    # --------------------------
    # Brand Impersonation Check
    # --------------------------
    for brand in BRANDS:
        if brand in domain:
            # Allow official domains only
            if not (
                domain == f"{brand}.com"
                or domain.endswith(f".{brand}.com")
            ):
                reasons.append(f"Brand impersonation detected: {brand}")
                return "PHISHING", reasons, "HIGH"

    # --------------------------
    # Typosquatting
    # --------------------------
    if features.get("possible_typosquat"):
        reasons.append("Typosquatting attack detected")
        return "PHISHING", reasons, "HIGH"

    # --------------------------
    # Feature-Based Scoring
    # --------------------------
    risk_weights = {
        "has_ip": 5,
        "has_punycode": 5,
        "has_at_symbol": 3,
        "shortened_url": 3,
        "suspicious_subdomain": 3,
        "redirect_pattern": 3,
        "has_hyphen": 1,
        "has_numbers_in_domain": 1,
        "long_subdomain": 1,
    }

    for feature, weight in risk_weights.items():
        if features.get(feature):
            score += weight
            reasons.append(feature.replace("_", " ").capitalize())

    # --------------------------
    # Final Classification
    # --------------------------
    if score >= 6:
        return "PHISHING", reasons, "HIGH"
    elif score >= 3:
        return "SUSPICIOUS", reasons, "MEDIUM"
    elif score >= 1:
        return "LOW RISK", reasons, "LOW"
    else:
        return "LEGITIMATE", reasons, "LOW"


# ==============================
# BRUTE FORCE DETECTION ENGINE
# ==============================

class BruteForceDetector:
    def __init__(self, threshold=3, time_window=60):
        self.threshold = threshold
        self.time_window = time_window  # seconds
        self.failed_attempts = defaultdict(list)

    def process_event(self, event):
        """
        Event format expected:
        {
            "ip": "192.168.1.10",
            "failed_login": True
        }
        """

        ip = event.get("ip")
        failed = event.get("failed_login")

        if not ip or not failed:
            return None

        current_time = time.time()
        self.failed_attempts[ip].append(current_time)

        # Keep only recent attempts within time window
        self.failed_attempts[ip] = [
            t for t in self.failed_attempts[ip]
            if current_time - t <= self.time_window
        ]

        if len(self.failed_attempts[ip]) >= self.threshold:
            return {
                "type": "BRUTE_FORCE",
                "ip": ip,
                "attempts": len(self.failed_attempts[ip]),
                "severity": "HIGH",
                "timestamp": current_time
            }

        return None
