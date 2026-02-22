import os
import time
import sys
from datetime import datetime

from detection.threat_engine import (
    detect_phishing,
    detect_bruteforce,
    detect_bruteforce_success
)
from alerts.alert_manager import generate_alert, Colors
from features.feature_extraction import extract_features
from parser.log_parser import parse_auth_log


# ==========================
# 🖥️ UI FUNCTIONS
# ==========================

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def loading_animation(text, duration=2):
    print(f"{Colors.CYAN}{text}{Colors.RESET}", end="")
    for _ in range(duration * 3):
        time.sleep(0.3)
        print(".", end="", flush=True)
    print()


def boot_sequence():
    clear_screen()
    print(f"{Colors.GREEN}Initializing SOC Engine{Colors.RESET}")
    loading_animation("Loading threat modules")
    loading_animation("Connecting to detection core")
    loading_animation("Activating correlation engine")
    loading_animation("Verifying log pipeline")
    print(f"{Colors.GREEN}System Ready ✔{Colors.RESET}")
    time.sleep(1)
    clear_screen()


def show_banner():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"{Colors.CYAN}")
    print(" ███████╗ ██████╗  ██████╗ ")
    print(" ██╔════╝██╔═══██╗██╔════╝ ")
    print(" ███████╗██║   ██║██║      ")
    print(" ╚════██║██║   ██║██║      ")
    print(" ███████║╚██████╔╝╚██████╗ ")
    print(" ╚══════╝ ╚═════╝  ╚═════╝ ")
    print("")
    print("      SOC Threat Detection System")
    print("               v1.1.0")
    print(f"{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.YELLOW}  System Time : {now}{Colors.RESET}")
    print(f"{Colors.YELLOW}  Type 'exit' or 'quit' to stop the system{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*60}{Colors.RESET}\n")


# ==========================
# 🚀 MAIN SYSTEM LOOP
# ==========================

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

            # ==========================
            # 🔎 PHISHING DETECTION
            # ==========================
            print(f"\n{Colors.CYAN}{'─'*60}")
            print(" PHISHING ANALYSIS")
            print(f"{'─'*60}{Colors.RESET}")

            features = extract_features(user_input)
            result, reasons, severity = detect_phishing(features)
            generate_alert(user_input, result, reasons, severity)

            # ==========================
            # 📊 SOC LOG ANALYSIS
            # ==========================
            print(f"\n{Colors.CYAN}{'─'*60}")
            print(" SOC LOG ANALYSIS")
            print(f"{'─'*60}{Colors.RESET}")

            events = parse_auth_log("logs/sample_auth.log")

            bruteforce_alerts = detect_bruteforce(events)

            if bruteforce_alerts:
                for alert in bruteforce_alerts:
                    print(f"{Colors.RED}⚠ {alert}{Colors.RESET}")
            else:
                print(f"{Colors.GREEN}✔ No brute-force activity detected.{Colors.RESET}")

            correlation_alerts = detect_bruteforce_success(events)

            if correlation_alerts:
                for alert in correlation_alerts:
                    print(f"{Colors.MAGENTA}🔥 {alert}{Colors.RESET}")
            else:
                print(f"{Colors.GREEN}✔ No correlated attack activity detected.{Colors.RESET}")

            print(f"\n{Colors.BLUE}{'='*60}{Colors.RESET}\n")

    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}Interrupted by user. Exiting safely...{Colors.RESET}")
        time.sleep(1)


if __name__ == "__main__":
    main()