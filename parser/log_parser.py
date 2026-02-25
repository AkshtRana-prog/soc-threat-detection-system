import re


def parse_auth_log(file_path):
    """
    Parse auth log from file path (STATIC mode).
    """
    parsed_events = []

    with open(file_path, "r") as file:
        lines = file.readlines()

    return parse_auth_log_from_lines(lines)


def parse_auth_log_from_lines(lines):
    """
    Parse auth log from list of log lines (LIVE mode compatible).
    """
    parsed_events = []

    for line in lines:
        event = {}

        line = line.strip()

        # ==============================
        # Extract IP Address
        # ==============================
        ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
        event["ip"] = ip_match.group() if ip_match else None

        # ==============================
        # Detect Failed Login
        # ==============================
        event["failed_login"] = "failed" in line.lower()

        # ==============================
        # Detect Successful Login
        # ==============================
        event["successful_login"] = "accepted" in line.lower() or "success" in line.lower()

        # ==============================
        # Detect Admin / Privilege Activity
        # ==============================
        event["admin_activity"] = "sudo" in line.lower() or "admin" in line.lower()

        # ==============================
        # Raw Log Line
        # ==============================
        event["raw"] = line

        parsed_events.append(event)

    return parsed_events
