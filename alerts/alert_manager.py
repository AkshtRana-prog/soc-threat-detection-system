class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"


def generate_alert(input_data, status, reasons, severity):
    print(f"{Colors.BLUE}\n=== Detection Result ==={Colors.RESET}")

    # -------------------------
    # Status Coloring
    # -------------------------
    if status.upper() == "PHISHING":
        status_color = Colors.RED
    elif status.upper() == "SUSPICIOUS":
        status_color = Colors.YELLOW
    else:
        status_color = Colors.GREEN

    print(f"Status   : {status_color}{status}{Colors.RESET}")

    # -------------------------
    # Severity Coloring
    # -------------------------
    if severity.upper() == "HIGH":
        severity_color = Colors.RED
    elif severity.upper() == "MEDIUM":
        severity_color = Colors.MAGENTA
    elif severity.upper() == "LOW":
        severity_color = Colors.GREEN
    else:
        severity_color = Colors.YELLOW

    print(f"Severity : {severity_color}{severity}{Colors.RESET}")

    # -------------------------
    # Reasons
    # -------------------------
    if reasons:
        print(f"{Colors.CYAN}\nReasons:{Colors.RESET}")
        for reason in reasons:
            print(f"- {reason}")

    print(f"{Colors.BLUE}{'-'*60}{Colors.RESET}")
