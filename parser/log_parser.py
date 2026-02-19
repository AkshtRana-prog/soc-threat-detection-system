import re


def parse_auth_log(file_path):
    parsed_events = []

    with open(file_path, "r") as file:
        for line in file:
            event = {}

            # Extract IP
            ip_match = re.search(r"\d{1,3}(\.\d{1,3}){3}", line)
            if ip_match:
                event["ip"] = ip_match.group()

            # Detect failed login
            if "failed" in line.lower():
                event["failed_login"] = True
            else:
                event["failed_login"] = False

            # Detect admin activity
            if "admin" in line.lower():
                event["admin_activity"] = True
            else:
                event["admin_activity"] = False

            event["raw"] = line.strip()

            parsed_events.append(event)

    return parsed_events
