import os
import time
from datetime import datetime
from zoneinfo import ZoneInfo  # Python 3.9+

from detection.threat_engine import (
    detect_phishing,
    detect_bruteforce,
    detect_bruteforce_success
)
from alerts.alert_manager import generate_alert, Colors
from features.feature_extraction import extract_features
from parser.log_parser import parse_auth_log


# ==================================================
# SYSTEM CONFIGURATION
# ==================================================

LOG_FILE_PATH = "logs/sample_auth.log"
ALERT_LOG_PATH = "alerts/alerts.log"
VERSION = "v1.1.2"
DEVELOPER = "Aksht Rana"
TIMEZONE = ZoneInfo("Asia/Kolkata")  # Force IST


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

    if phishing_result == "Phishing":
        score += 50

    if bruteforce_alerts:
        score += 30

    if correlation_alerts:
        score += 40

    return score


def classify_risk(score):
    if score >= 90:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"


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
    print(f"{Colors.YELLOW} Type 'exit' or 'quit' to stop the system{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*60}{Colors.RESET}\n")


# ==================================================
# MAIN LOOP
# ==================================================

def main():
    boot_sequence()
    show_banner()

    try:
        while True:
            user_input = input(
                f"{Colors.GREEN}➤ Enter URL / Email > {Colors.RESET}"
            ).strip()

            if user_input.lower() in ["exit", "quit"]:
                print(f"\n{Colors.CYAN}Shutting down SOC Engine...{Colors.RESET}")
                time.sleep(1)
                break

            if not user_input:
                print(f"{Colors.YELLOW}Input cannot be empty.{Colors.RESET}\n")
                continue

            # ==========================================
            # PHISHING ANALYSIS
            # ==========================================
            print(f"\n{Colors.CYAN}{'─'*60}")
            print(" PHISHING ANALYSIS")
            print(f"{'─'*60}{Colors.RESET}")

            features = extract_features(user_input)
            result, reasons, severity = detect_phishing(features)

            generate_alert(user_input, result, reasons, severity)
            log_alert(f"Phishing Check | Input: {user_input} | Result: {result}")

            # ==========================================
            # SOC LOG ANALYSIS
            # ==========================================
            print(f"\n{Colors.CYAN}{'─'*60}")
            print(" SOC LOG ANALYSIS")
            print(f"{'─'*60}{Colors.RESET}")

            events = parse_auth_log(LOG_FILE_PATH)

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

            # ==========================================
            # RISK SCORING
            # ==========================================
            score = calculate_risk_score(result, bruteforce_alerts, correlation_alerts)
            risk_level = classify_risk(score)

            print(f"\n{Colors.BLUE}{'='*60}{Colors.RESET}")
            print(f"{Colors.YELLOW} Risk Score : {score}{Colors.RESET}")

            if risk_level == "CRITICAL":
                print(f"{Colors.RED} Threat Level : {risk_level}{Colors.RESET}")
            elif risk_level == "HIGH":
                print(f"{Colors.MAGENTA} Threat Level : {risk_level}{Colors.RESET}")
            elif risk_level == "MEDIUM":
                print(f"{Colors.YELLOW} Threat Level : {risk_level}{Colors.RESET}")
            else:
                print(f"{Colors.GREEN} Threat Level : {risk_level}{Colors.RESET}")

            print(f"{Colors.BLUE}{'='*60}{Colors.RESET}\n")

            log_alert(f"Final Risk Level: {risk_level} | Score: {score}")

    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}Interrupted by user. Exiting safely...{Colors.RESET}")
        time.sleep(1)


if __name__ == "__main__":
    main()