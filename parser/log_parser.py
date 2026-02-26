import re

FAILED_PATTERN = re.compile(r"Failed password .* from (\d+\.\d+\.\d+\.\d+)")
SUCCESS_PATTERN = re.compile(r"Accepted password .* from (\d+\.\d+\.\d+\.\d+)")

def parse_auth_log_from_lines(lines):
    events = []

    for line in lines:

        # Ignore SOC alert lines
        if "Phishing" in line or "Risk Level" in line:
            continue

        failed_match = FAILED_PATTERN.search(line)
        success_match = SUCCESS_PATTERN.search(line)

        if failed_match:
            events.append({
                "ip": failed_match.group(1),
                "failed_login": True,
                "successful_login": False
            })

        elif success_match:
            events.append({
                "ip": success_match.group(1),
                "failed_login": False,
                "successful_login": True
            })

    return events