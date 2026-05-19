# AI-ASSISTED INTRUSION DETECTION & RESPONSE SYSTEM (IDRS)

**Detect, Respond, Defend — Always One Step Ahead**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-black)
![Scapy](https://img.shields.io/badge/Scapy-Live%20Capture-green)
![scikit-learn](https://img.shields.io/badge/scikit--learn-Isolation%20Forest-orange)
![License](https://img.shields.io/badge/License-Academic%20Project-lightgrey)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Index](#project-index)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Testing](#testing)
- [Dataset](#dataset)
- [References](#references)

---

## Overview

IDRS is a **lightweight, hybrid Network Intrusion Detection & Prevention System (NIDS/NIPS)** that combines **rule-based detection** for known attack signatures with **unsupervised Machine Learning (Isolation Forest)** for zero-day anomaly detection. Built on Ubuntu with Python, it captures live network traffic, detects malicious behavior in real time, and automatically blocks attacker IPs via `iptables` — all monitored through a web-based Security Operations Center (SOC) dashboard.

Developed as a Final Year Project at **Universiti Kuala Lumpur (UniKL MIIT)** under the supervision of **Ts. Wan Hazimah Wan Ismail**.

---

## Features

| Component | Details |
|-----------|---------|
| ⚙️ **Architecture** | Modular design separating packet capture, rule detection, ML anomaly scoring, prevention, and dashboard layers |
| 🤖 **AI / ML** | Unsupervised Isolation Forest trained on CICIDS2017 benign traffic; detects unknown anomalies without labeled attack data |
| 📡 **Packet Capture** | Real-time sniffing via Scapy on promiscuous mode (`enp0s3`) |
| 🛡️ **Rule Engine** | Threshold-based detection: DoS Flood (&gt;100 pkts/10s) and Port Scan (&gt;10 ports/10s) |
| 🔒 **Auto-Prevention** | Kernel-level IP blocking via `iptables` with escalating durations (30 min → permanent) |
| 🌐 **SOC Dashboard** | Flask-based web interface with live threat feed, blocked IP management, manual unblock, and session authentication |
| 🗄️ **Audit Logging** | SQLite database records every alert, anomaly score, and prevention action with timestamps |
| 🧪 **Testing** | Controlled attack simulation across 3-VM VirtualBox topology (IDS, Attacker, Victim) |
| ⚡ **Performance** | Lightweight CPU-only deployment; no GPU required |
| 🔧 **Modularity** | Separate modules for feature extraction, model inference, detection logic, and response handling |

---

## Project Index

```text
AI-ASSISTED-INTRUSION-DETECTION-RESPONSE-SYSTEM/
│
├── Manual_Rules_Fast.py      # Main IDS engine (capture + detection + blocking)
├── ml_detector.py            # Real-time ML anomaly detector (Isolation Forest)
├── dashboard.py              # Flask web dashboard (SOC interface)
├── retrain_model.py          # Model training script (CICIDS2017 → Isolation Forest)
├── init_db.py                # Database initialization (alerts, blocked_ips, admins)
├── py.py                     # Admin user seed script
├── idrs.db                   # SQLite database (auto-generated)
├── config.json               # Detection thresholds configuration
│
├── scr/
│   └── train_isolation_forest.py  # Full CICIDS2017 training pipeline
│
├── models/
│   ├── idrs_if_model.pkl     # Trained Isolation Forest model
│   ├── idrs_scaler.pkl       # RobustScaler artifact
│   ├── idrs_selector.pkl     # SelectKBest feature selector
│   └── idrs_features.json    # Feature metadata & threshold
│
├── templates/
│   ├── login.html            # Admin authentication page
│   └── index.html            # Live SOC dashboard (Tailwind CSS)
│
├── data/                     # CICIDS2017 dataset folder (not in repo)
│   └── .csv                  # Download separately (see Dataset section)
│
├── requirements.txt          # Python dependencies
└── .gitignore                # Excludes venv, data/.csv, models/*.pkl
```

---

## Getting Started

### Prerequisites

This project requires the following dependencies:

- **Programming Language:** Python 3.10+
- **Operating System:** Ubuntu 22.04 (or compatible Linux distribution)
- **Privileges:** `sudo` access (required for `iptables` and promiscuous mode)
- **Virtualization:** Oracle VM VirtualBox (for lab topology)

### Installation

Build IDRS from the source and install dependencies:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/AimanAzmi03/AI-ASSISTED-INTRUSION-DETECTION-RESPONSE-SYSTEM.git
   cd AI-ASSISTED-INTRUSION-DETECTION-RESPONSE-SYSTEM

2. **Create and activate a Python virtual environment:***
   ```bash
   python -m venv venv
   source venv/bin/activate

3. **Install the dependencies:**
   ```bash
   pip install -r requirements.txt

4. **Initialize the database and create the admin user:**
   ```bash
   python init_db.py
   python py.py

5. **Train the ML model (if models/ folder is empty):**
   ```bash
   python retrain_model.py

### Usage

Run the system components in separate terminals:

**Terminal 1 — Start the Detection Engine:**
   ```bash
   sudo python Manual_Rules_Fast.py
   ```
| Requires sudo for Scapy packet capture and iptables manipulation.

**Terminal 2 — Start the Dashboard:**
   ```bash
   source venv/bin/activate
   python dashboard.py
   ```

**Access the SOC Dashboard:**
- Open browser to: http://192.168.56.103:5000
- Login with credentials created in py.py (default: admin / admin123)

**Testing**
IDRS uses controlled attack simulation for validation. Run these from the Attacker VM (192.168.56.101) while the IDS is active:
| Test | Command	Expected | Result |
|-----------|---------|-----------|
| **DoS Flood**	| sudo hping3 --icmp --flood 192.168.56.102	| Rule alert + iptables block within 10s ||
| **Port Scan**	| sudo nmap 192.168.56.102	| Rule alert + block within 5s |
| **ML Anomaly** | ping -s 65500 -c 5 192.168.56.102	| ML alert after flow timeout (~15s) |
| **Volume Test**	| cat /dev/zero | nc 192.168.56.102 9999 | ML anomaly detected & blocked |

Verify blocks on the IDS VM:
   ```bash
   sudo iptables -L INPUT -n -v --line-numbers
   sqlite3 idrs.db "SELECT * FROM alerts ORDER BY id DESC LIMIT 5;"
   ```

---

### Dataset
The CICIDS2017 dataset is required for training but not included in this repository due to GitHub's 100MB file size limit.
- **Download:** Canadian Institute for Cybersecurity — CICIDS2017
- **Place files in:** data/ folder
- **Required for training:** Monday-WorkingHours.pcap_ISCX.csv (benign training data)
- **Optional for validation:** Wednesday-workingHours.pcap_ISCX.csv (mixed traffic)

---

### References
- Abraham, J. A., & Bindu, V. R. (2021). Intrusion Detection and Prevention in Networks Using ML & DL: A Review. IEEE ICAECA.
- Fernando, G.-P., Florina, A. M., & Liliana, C.-B. (2024). Evaluation of Unsupervised Learning Algorithms for Intrusion Detection. IEEE Access, 12, 190134–190157.
- Guo, F., et al. (2024). Information Security NIDS Based on ML. IEEE ICDSNS.
- Rahman, M. S., et al. (2024). Enhancing Cybersecurity with NIDS Using ML. IEEE RAAICON.
- Usuzaki, S., & Saito, R. (2024). An Architecture of NIDPS for Seamless Deployments. IEEE GCCE.

---

- **Developed by:** Muhammad Aiman Bin Noor Azmi (52215224160)
- **Supervisor:** Ts. Wan Hazimah Wan Ismail
- **Institution:** Universiti Kuala Lumpur, Malaysian Institute of Information Technology (UniKL MIIT)
