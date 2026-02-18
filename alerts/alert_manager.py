class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    RESET = "\033[0m"


def generate_alert(input_data, status, reasons, severity):
    print("\n=== Detection Result ===")
    print(f"Status   : {status}")
    print(f"Severity : {severity}")

    if reasons:
        print("\nReasons:")
        for reason in reasons:
            print(f"- {reason}")
