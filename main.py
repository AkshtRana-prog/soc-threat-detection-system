import os
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from ingestion.log_reader import read_static_logs, read_live_logs
from parser.log_parser import parse_auth_log_from_lines
from detection.threat_engine import (
    detect_phishing,
    detect_bruteforce,
    detect_bruteforce_success
)
from alerts.alert_manager import generate_alert, Colors
from features.feature_extraction import extract_features


# ==================================================
# SYSTEM CONFIGURATION
# ==================================================

LOG_FILE_PATH = "logs/sample_auth.log"
ALERT_LOG_PATH = "alerts/alerts.log"
VERSION = "v1.2.4"
DEVELOPER = "Aksht Rana"
TIMEZONE = ZoneInfo("Asia/Kolkata")

LIVE_EVENT_BUFFER = []  # Persistent buffer for live mode


# ==================================================
# UTILITY FUNCTIONS
# ==================================================

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def get_current_time():
    return datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S IST")


def loading_animation(text, duration=2):
    print(f"{Colors.CYAN}{text}{Colors.RESET}", end="")
    for _ in range(duration * 3):
        time.sleep(0.3)
        print(".", end="", flush=True)
    print()


def log_alert(alert_text):
    os.makedirs("alerts", exist_ok=True)
    with open(ALERT_LOG_PATH, "a") as f:
        f.write(f"{get_current_time()} | {alert_text}\n")


def calculate_risk_score(phishing_result, bruteforce_alerts, correlation_alerts):
    score = 0

    if phishing_result.upper() == "PHISHING":
        score += 40
    elif phishing_result.upper() == "SUSPICIOUS":
        score += 20

    score += min(len(bruteforce_alerts) * 10, 30)

    if correlation_alerts:
        score += 25

    return min(score, 100)


def classify_risk(score):
    if score >= 90:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"


def validate_log_file(path):
    if not os.path.exists(path):
        print(f"{Colors.RED}Log file not found: {path}{Colors.RESET}")
        exit(1)


# ==================================================
# MODE SELECTION
# ==================================================

def select_mode():
    print("\nSelect Monitoring Mode:")
    print("1. Static Log Analysis")
    print("2. Live Log Monitoring")

    while True:
        try:
            choice = input("Enter choice (1/2): ").strip()
        except KeyboardInterrupt:
            print(f"\n{Colors.CYAN}Interrupted by user. Exiting safely...{Colors.RESET}")
            exit(0)

        if choice == "1":
            return "STATIC"
        elif choice == "2":
            return "LIVE"
        else:
            print("Invalid choice. Please enter 1 or 2.")


# ==================================================
# UI COMPONENTS
# ==================================================

def boot_sequence():
    clear_screen()
    print(f"{Colors.GREEN}Initializing SOC Engine {VERSION} | {DEVELOPER}{Colors.RESET}")
    loading_animation("Loading threat modules")
    loading_animation("Starting correlation engine")
    loading_animation("Connecting log pipeline")
    loading_animation("Performing integrity check")
    print(f"{Colors.GREEN}System Ready ✔{Colors.RESET}")
    time.sleep(1)
    clear_screen()


def show_banner():
    print(f"{Colors.CYAN}")
    print(" ███████╗ ██████╗  ██████╗ ")
    print(" ██╔════╝██╔═══██╗██╔════╝ ")
    print(" ███████╗██║   ██║██║      ")
    print(" ╚════██║██║   ██║██║      ")
    print(" ███████║╚██████╔╝╚██████╗ ")
    print(" ╚══════╝ ╚═════╝  ╚═════╝ ")
    print("")
    print("      SOC Threat Detection System")
    print(f"               Version {VERSION}")
    print("")
    print(f"      Developed by {DEVELOPER}")
    print(f"{Colors.RESET}")

    print(f"{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.YELLOW} System Time : {get_current_time()}{Colors.RESET}")
    print(f"{Colors.YELLOW} Timezone    : Asia/Kolkata (IST){Colors.RESET}")
    print(f"{Colors.BLUE}{'='*60}{Colors.RESET}\n")


# ==================================================
# LOG ANALYSIS HANDLER
# ==================================================

def process_events(events):
    bruteforce_alerts = detect_bruteforce(events)
    correlation_alerts = detect_bruteforce_success(events)

    if bruteforce_alerts:
        for alert in bruteforce_alerts:
            print(f"{Colors.RED}⚠ {alert}{Colors.RESET}")
            log_alert(alert)
    else:
        print(f"{Colors.GREEN}✔ No brute-force activity detected.{Colors.RESET}")

    if correlation_alerts:
        for alert in correlation_alerts:
            print(f"{Colors.MAGENTA}⚠ {alert}{Colors.RESET}")
            log_alert(alert)
    else:
        print(f"{Colors.GREEN}✔ No correlated attack activity detected.{Colors.RESET}")

    return bruteforce_alerts, correlation_alerts

# ==================================================
# MAIN LOOP
# ==================================================

def main():
    validate_log_file(LOG_FILE_PATH)

    boot_sequence()
    show_banner()

    mode = select_mode()

    try:
        while True:

            try:
                user_input = input(
                    f"{Colors.GREEN}➤ Enter URL / Email > {Colors.RESET}"
                ).strip()
            except KeyboardInterrupt:
                print(f"\n{Colors.CYAN}Interrupted by user. Exiting safely...{Colors.RESET}")
                break

            if user_input.lower() in ["exit", "quit"]:
                print(f"\n{Colors.CYAN}Shutting down SOC Engine...{Colors.RESET}")
                break

            if not user_input:
                continue

            # ==========================
            # PHISHING ANALYSIS
            # ==========================
            print(f"\n{Colors.CYAN}{'─'*60}")
            print(" PHISHING ANALYSIS")
            print(f"{'─'*60}{Colors.RESET}")

            features = extract_features(user_input)
            result, reasons, severity = detect_phishing(features)

            generate_alert(user_input, result, reasons, severity)
            log_alert(f"Phishing | Input: {user_input} | Result: {result}")

            # ==========================
            # LOG ANALYSIS
            # ==========================
            print(f"\n{Colors.CYAN}{'─'*60}")
            print(" SOC LOG ANALYSIS")
            print(f"{'─'*60}{Colors.RESET}")

            if mode == "STATIC":
                log_lines = read_static_logs(LOG_FILE_PATH)
                parsed_events = parse_auth_log_from_lines(log_lines)
                bruteforce_alerts, correlation_alerts = process_events(parsed_events)

            elif mode == "LIVE":
                print(f"{Colors.YELLOW}Live Monitoring Active... Press Ctrl+C to stop.{Colors.RESET}")

                try:
                    for line in read_live_logs(LOG_FILE_PATH):
                        print(f"{Colors.BLUE}[NEW LOG]{Colors.RESET} {line.strip()}")

                        parsed = parse_auth_log_from_lines([line.strip()])
                        LIVE_EVENT_BUFFER.extend(parsed)

                        # Keep only last 200 events (sliding window)
                        if len(LIVE_EVENT_BUFFER) > 200:
                            LIVE_EVENT_BUFFER.pop(0)

                        bruteforce_alerts, correlation_alerts = process_events(LIVE_EVENT_BUFFER)

                except KeyboardInterrupt:
                    print(f"\n{Colors.CYAN}Live monitoring stopped.{Colors.RESET}")
                    continue

                continue

            # ==========================
            # RISK SCORING
            # ==========================
            score = calculate_risk_score(result, bruteforce_alerts, correlation_alerts)
            risk_level = classify_risk(score)

            print(f"\n{Colors.BLUE}{'='*60}{Colors.RESET}")
            print(f"{Colors.YELLOW} Risk Score : {score}{Colors.RESET}")
            print(f"{Colors.RED if risk_level in ['HIGH','CRITICAL'] else Colors.YELLOW if risk_level=='MEDIUM' else Colors.GREEN} Threat Level : {risk_level}{Colors.RESET}")
            print(f"{Colors.BLUE}{'='*60}{Colors.RESET}\n")

            log_alert(f"Final Risk Level: {risk_level} | Score: {score}")

    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}Interrupted by user. Exiting safely...{Colors.RESET}")


if __name__ == "__main__":
    main()
