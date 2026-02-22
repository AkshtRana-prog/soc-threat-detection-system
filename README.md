🛡️ Mini SOC / SIEM Detection Engine

A lightweight Python-based Mini SIEM (Security Information and Event Management) engine that performs:

🔍 Phishing & domain threat detection

🔐 Brute-force attack detection

📂 Log parsing & analysis

🚨 Alert generation with severity levels

This project simulates core SIEM functionalities similar to tools like Splunk — but built from scratch for learning and experimentation.

🚀 Features
🔎 Domain Threat Detection

Brand impersonation detection

Fuzzy typosquatting detection (e.g., go0glr.com)

Suspicious subdomain detection

IP-based URLs

Punycode detection

Redirect pattern detection

Risk scoring classification

🔐 Brute Force Detection

Parses authentication logs

Detects repeated failed login attempts

Configurable threshold

IP-based alert generation

🖥 Graceful CLI Interface

Clean terminal UI

Color-coded alerts

Safe exit handling (CTRL+C supported)

📁 Project Structure
soc-detection-engine/
│
├── alerts/              # Alert generation & formatting
├── detection/           # Threat detection engine
├── features/            # Feature extraction logic
├── parser/              # Log parsing module
├── logs/                # Sample log files
├── reports/             # (Future use)
├── main.py              # Entry point
└── README.md

⚙️ How It Works

User inputs a URL or email text

Feature extraction module analyzes indicators

Threat engine applies detection logic & scoring

Log parser analyzes authentication logs

Alerts are generated with severity classification

▶️ How To Run

Make sure you are in the project root directory:

python3 main.py


Type exit or quit to stop.

🧠 Example Detection

Input:

go0glr.com


Output:

Status   : PHISHING
Severity : HIGH
Reason   : Typosquatting detected (similar to google)

🛠 Future Improvements

Live log monitoring

Multi-file ingestion

Event indexing

Query/search functionality

Correlation engine

JSON report export

Dashboard interface

🎯 Purpose

This project is built to:

Understand SIEM architecture

Learn detection engineering

Practice log analysis

Build a cybersecurity portfolio project

👨‍💻 Author

Aksht Rana
Cybersecurity Enthusiast | SOC & Detection Engineering