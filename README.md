# 🛡️ Mini SOC / SIEM Detection Engine

A lightweight Python-based **Mini SIEM (Security Information and Event Management) engine** that performs:

- 🔍 Phishing & domain threat detection  
- 🔐 Brute-force attack detection  
- 📂 Log parsing & analysis  
- 🚨 Alert generation with severity levels  

This project simulates core SIEM functionalities similar to tools like Splunk — built from scratch for learning and experimentation.

---

## 🚀 Features

### 🔎 Domain Threat Detection
- Brand impersonation detection
- Fuzzy typosquatting detection (e.g., `go0glr.com`)
- Suspicious subdomain detection
- IP-based URLs detection
- Punycode detection
- Redirect pattern detection
- Risk scoring classification system

### 🔐 Brute Force Detection
- Parses authentication logs
- Detects repeated failed login attempts
- Configurable threshold
- IP-based alert generation

### 🖥 CLI Interface
- Clean terminal UI
- Color-coded alerts
- Graceful exit handling (CTRL+C supported)

---

## 📁 Project Structure

```
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
```

---

## ⚙️ How It Works

1. User inputs a URL or email text  
2. Feature extraction module analyzes threat indicators  
3. Threat engine applies detection logic & scoring  
4. Log parser analyzes authentication logs  
5. Alerts are generated with severity classification  

---

## ▶️ How To Run

Make sure you are inside the project root directory:

```bash
python3 main.py
```

Type `exit` or `quit` to stop the program.

---

## 🧠 Example Detection

**Input:**
```
go0glr.com
```

**Output:**
```
Status   : PHISHING
Severity : HIGH
Reason   : Typosquatting detected (similar to google)
```

---



## 🛠 Future Improvements

- Live log monitoring
- Multi-file ingestion
- Event indexing
- Search/query functionality
- Correlation engine
- JSON report export
- Dashboard interface

---

## 🎯 Purpose

This project is built to:

- Understand SIEM architecture
- Learn detection engineering
- Practice log analysis
- Build a cybersecurity portfolio project

---

## 👨‍💻 Author

**Aksht Rana**  
Cybersecurity Enthusiast | SOC & Detection Engineering
