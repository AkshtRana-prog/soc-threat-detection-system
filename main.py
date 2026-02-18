from detection.rule_engine import check_phishing
from alerts.alert_manager import generate_alert, Colors
from features.feature_extraction import extract_features


def main():
    print(f"{Colors.CYAN}=== SOC Phishing Detection System ==={Colors.RESET}")
    print(f"{Colors.BLUE}Type 'exit' or 'quit' to stop.{Colors.RESET}\n")

    while True:
        user_input = input(
            f"{Colors.BLUE}Enter URL or Email text:{Colors.RESET} "
        ).strip()

        if user_input.lower() in ["exit", "quit"]:
            print(f"\n{Colors.CYAN}Exiting...{Colors.RESET}")
            break

        if not user_input:
            print(f"{Colors.YELLOW}Input cannot be empty.{Colors.RESET}\n")
            continue

        features = extract_features(user_input)
        result, reasons, severity = check_phishing(features)

        generate_alert(user_input, result, reasons, severity)


if __name__ == "__main__":
    main()
