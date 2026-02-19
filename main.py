from detection.threat_engine import detect_phishing, detect_bruteforce
from alerts.alert_manager import generate_alert, Colors
from features.feature_extraction import extract_features
from parser.log_parser import parse_auth_log


def main():
    print(f"{Colors.CYAN}=== SOC Threat Detection System ==={Colors.RESET}")
    print(f"{Colors.BLUE}Type 'exit' or 'quit' to stop.{Colors.RESET}\n")

    try:
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

            # Phishing detection
            features = extract_features(user_input)
            result, reasons, severity = detect_phishing(features)
            generate_alert(user_input, result, reasons, severity)

            # Log analysis
            print("\n--- SOC Log Analysis ---")
            events = parse_auth_log("logs/sample_auth.log")
            bruteforce_alerts = detect_bruteforce(events)

            if bruteforce_alerts:
                for alert in bruteforce_alerts:
                    print("⚠", alert)
            else:
                print("No brute-force activity detected.")

            print("\n---------------------------------\n")

    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}Interrupted by user. Exiting safely...{Colors.RESET}")



if __name__ == "__main__":
    main()
