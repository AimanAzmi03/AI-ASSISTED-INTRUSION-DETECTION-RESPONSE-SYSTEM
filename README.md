
readme_content = '''# AI-ASSISTED INTRUSION DETECTION & RESPONSE SYSTEM (IDRS)

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
- [System Architecture](#system-architecture)
- [VM Topology & Network Setup](#vm-topology--network-setup)
  - [VirtualBox Host Network Manager](#virtualbox-host-network-manager)
  - [VM Network Adapter Settings](#vm-network-adapter-settings)
  - [Netplan Configuration](#netplan-configuration)
  - [Enable IP Forwarding on IDS](#enable-ip-forwarding-on-ids)
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
| 📡 **Packet Capture** | Real-time sniffing via Scapy on promiscuous mode (`enp0s8` & `enp0s9`) |
| 🛡️ **Rule Engine** | Threshold-based detection: DoS Flood (>100 pkts/10s) and Port Scan (>10 ports/10s) |
| 🔒 **Auto-Prevention** | Kernel-level IP blocking via `iptables` with escalating durations (30 min → permanent) |
| 🌐 **SOC Dashboard** | Flask-based web interface with live threat feed, blocked IP management, manual unblock, and session authentication |
| 🗄️ **Audit Logging** | SQLite database records every alert, anomaly score, and prevention action with timestamps |
| 🧪 **Testing** | Controlled attack simulation across 3-VM VirtualBox topology (IDS, Attacker, Victim) |
| ⚡ **Performance** | Lightweight CPU-only deployment; no GPU required |
| 🔧 **Modularity** | Separate modules for feature extraction, model inference, detection logic, and response handling |

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              VIRTUALBOX HOST                             │
│  ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐  │
│  │   ATTACKER VM   │      │     IDS VM      │      │    VICTIM VM    │  │
│  │  192.168.56.101 │◄────►│ 192.168.56.103  │◄────►│ 192.168.57.102  │  │
│  │                 │      │ 192.168.57.103  │      │                 │  │
│  │  NAT + Host-Only│      │  NAT + Host-Only│      │  NAT + Host-Only│  │
│  │     #1          │      │  #1 + #2        │      │     #2          │  │
│  └─────────────────┘      └─────────────────┘      └─────────────────┘  │
│           │                        │                        │            │
│           └────────── 192.168.56.x ─┴──────── 192.168.57.x ─┘            │
│                                                                                          │
│  Traffic Flow: Attacker → IDS (enp0s8) → IDS (enp0s9) → Victim          │
│  IDS acts as inline gateway — all inter-VM traffic passes through it    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## VM Topology & Network Setup

This project requires **3 Ubuntu VMs** in VirtualBox with an **inline IDS topology**. The IDS VM sits between the Attacker and Victim, forcing all traffic to pass through it for real-time detection and blocking.

### IP Plan

| Network | Subnet | Purpose |
|---------|--------|---------|
| Host-Only #1 | `192.168.56.0/24` | Attacker ↔ IDS (left side) |
| Host-Only #2 | `192.168.57.0/24` | IDS ↔ Victim (right side) |

| VM | Role | Adapter 1 (NAT) | Adapter 2 (Host-Only #1) | Adapter 3 (Host-Only #2) |
|----|------|-----------------|--------------------------|--------------------------|
| **IDS** | Gateway + Detection | `enp0s3` (DHCP) | `enp0s8` — `192.168.56.103/24` | `enp0s9` — `192.168.57.103/24` |
| **Attacker** | Attack Source | `enp0s3` (DHCP) | `enp0s8` — `192.168.56.101/24` | — |
| **Victim** | Target | `enp0s3` (DHCP) | — | `enp0s8` — `192.168.57.102/24` |

> **Note:** Interface names (`enp0s3`, `enp0s8`, `enp0s9`) may vary. Run `ip link show` on each VM to confirm.

---

### VirtualBox Host Network Manager

Before configuring VMs, create and configure the two Host-Only adapters on your **Windows host**:

1. Open **VirtualBox Manager → File → Host Network Manager** (or **Tools → Network**)
2. **Adapter #1** (vboxnet0 / Host-Only #1):
   - IPv4 Address: `192.168.56.1`
   - IPv4 Network Mask: `255.255.255.0`
   - **DHCP Server: Unchecked / Disabled**
3. **Adapter #2** (vboxnet1 / Host-Only #2):
   - IPv4 Address: `192.168.57.1`
   - IPv4 Network Mask: `255.255.255.0`
   - **DHCP Server: Unchecked / Disabled**
4. Click **Apply**

---

### VM Network Adapter Settings

**Power off all 3 VMs** before changing these settings.

#### IDS VM
| Adapter | Attached To | Name | Promiscuous Mode |
|---------|-------------|------|------------------|
| Adapter 1 | NAT | — | Deny |
| Adapter 2 | Host-Only Adapter | VirtualBox Host-Only Ethernet Adapter #1 | **Allow All** |
| Adapter 3 | Host-Only Adapter | VirtualBox Host-Only Ethernet Adapter #2 | **Allow All** |

#### Attacker VM
| Adapter | Attached To | Name | Promiscuous Mode |
|---------|-------------|------|------------------|
| Adapter 1 | NAT | — | Deny |
| Adapter 2 | Host-Only Adapter | VirtualBox Host-Only Ethernet Adapter #1 | **Allow All** |

#### Victim VM
| Adapter | Attached To | Name | Promiscuous Mode |
|---------|-------------|------|------------------|
| Adapter 1 | NAT | — | Deny |
| Adapter 2 | Host-Only Adapter | VirtualBox Host-Only Ethernet Adapter #2 | **Allow All** |

> **Important:** All VMs on the same side must use the **same** Host-Only adapter. Promiscuous Mode must be set to **Allow All** on the Host-Only adapters so Scapy can capture traffic not destined for the IDS itself.

---

### Netplan Configuration

Boot each VM and verify interface names with `ip link show`. Then apply the netplan configs below.

#### IDS VM (`/etc/netplan/01-netcfg.yaml`)
```yaml
network:
  version: 2
  renderer: NetworkManager
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: no
      addresses:
        - 192.168.56.103/24
    enp0s9:
      dhcp4: no
      addresses:
        - 192.168.57.103/24
```

#### Attacker VM (`/etc/netplan/01-netcfg.yaml`)
```yaml
network:
  version: 2
  renderer: NetworkManager
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: no
      addresses:
        - 192.168.56.101/24
      routes:
        - to: 192.168.57.0/24
          via: 192.168.56.103
      nameservers:
        addresses:
          - 8.8.8.8
```

#### Victim VM (`/etc/netplan/01-netcfg.yaml`)
```yaml
network:
  version: 2
  renderer: NetworkManager
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: no
      addresses:
        - 192.168.57.102/24
      routes:
        - to: 192.168.56.0/24
          via: 192.168.57.103
      nameservers:
        addresses:
          - 8.8.8.8
```

**Apply on ALL 3 VMs:**
```bash
sudo chmod 600 /etc/netplan/01-netcfg.yaml
sudo netplan apply
sudo systemctl restart NetworkManager
```

---

### Enable IP Forwarding on IDS

The IDS VM must forward traffic between the two Host-Only networks so the Attacker can reach the Victim (and vice versa) through the IDS.

```bash
# Enable IP forwarding (temporary)
sudo sysctl -w net.ipv4.ip_forward=1

# Make it permanent
sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf

# Allow forwarding between Host-Only interfaces
sudo iptables -A FORWARD -i enp0s8 -o enp0s9 -j ACCEPT
sudo iptables -A FORWARD -i enp0s9 -o enp0s8 -j ACCEPT

# Save iptables rules
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```

**Enable promiscuous mode for packet capture:**
```bash
sudo ip link set enp0s8 promisc on
sudo ip link set enp0s9 promisc on
```

**Verify routing from Attacker:**
```bash
traceroute 192.168.57.102
```
You should see `192.168.56.103` as the first hop, confirming traffic flows through the IDS.

---

## Project Index

```text
AI-ASSISTED-INTRUSION-DETECTION-RESPONSE-SYSTEM/
│
├── idrs.py                   # Main IDS engine (capture + detection + blocking)
├── ml_detector.py            # Real-time ML anomaly detector (Isolation Forest)
├── app.py                    # Flask web dashboard (SOC interface)
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

- **Programming Language:** Python 3.10+
- **Operating System:** Ubuntu 22.04 (or compatible Linux distribution)
- **Privileges:** `sudo` access (required for `iptables` and promiscuous mode)
- **Virtualization:** Oracle VM VirtualBox with 2 Host-Only adapters configured (see [VM Topology](#vm-topology--network-setup))
- **Network:** 3 VMs (IDS, Attacker, Victim) with inline topology as described above

### Installation

Build IDRS from the source and install dependencies:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/AimanAzmi03/AI-ASSISTED-INTRUSION-DETECTION-RESPONSE-SYSTEM.git
   cd AI-ASSISTED-INTRUSION-DETECTION-RESPONSE-SYSTEM
   ```

2. **Create and activate a Python virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install the dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the database and create the admin user:**
   ```bash
   python init_db.py
   python py.py
   ```

5. **Train the ML model (if models/ folder is empty):**
   ```bash
   python retrain_model.py
   ```

### Usage

Run the system components in separate terminals on the **IDS VM**:

**Terminal 1 — Start the Detection Engine:**
```bash
sudo python idrs.py
```
> Requires sudo for Scapy packet capture and iptables manipulation.

**Terminal 2 — Start the Dashboard:**
```bash
source venv/bin/activate
python app.py
```

**Access the SOC Dashboard:**
- Open browser to: `http://192.168.56.103:5000` (or `http://192.168.57.103:5000`)
- Login with credentials created in `py.py` (default: `admin` / `admin123`)

### Testing

IDRS uses controlled attack simulation for validation. Run these from the **Attacker VM** (`192.168.56.101`) while the IDS is active:

| Test | Command | Expected Result |
|------|---------|---------------|
| **DoS Flood** | `sudo hping3 --icmp --flood 192.168.57.102` | Rule alert + iptables block within 10s |
| **Port Scan** | `sudo nmap 192.168.57.102` | Rule alert + block within 5s |
| **ML Anomaly** | `ping -s 65500 -c 5 192.168.57.102` | ML alert after flow timeout (~15s) |
| **Volume Test** | `cat /dev/zero | nc 192.168.57.102 9999` | ML anomaly detected & blocked |

Verify blocks on the IDS VM:
```bash
sudo iptables -L INPUT -n -v --line-numbers
sqlite3 idrs.db "SELECT * FROM alerts ORDER BY id DESC LIMIT 5;"
```

**Manual Unblock Test:**
1. Trigger an attack from the Attacker VM
2. Confirm the IP is blocked in the dashboard
3. Click **Unblock** on the dashboard
4. Wait ~10 seconds for the IDS sync loop to reset the tracker
5. Attack again — the IDS should re-detect the threat without restarting

---

## Dataset

The CICIDS2017 dataset is required for training but not included in this repository due to GitHub's 100MB file size limit.

- **Download:** [Canadian Institute for Cybersecurity — CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Place files in:** `data/` folder
- **Required for training:** `Monday-WorkingHours.pcap_ISCX.csv` (benign training data)
- **Optional for validation:** `Wednesday-workingHours.pcap_ISCX.csv` (mixed traffic)

---

## References

- Abraham, J. A., & Bindu, V. R. (2021). Intrusion Detection and Prevention in Networks Using ML & DL: A Review. *IEEE ICAECA*.
- Fernando, G.-P., Florina, A. M., & Liliana, C.-B. (2024). Evaluation of Unsupervised Learning Algorithms for Intrusion Detection. *IEEE Access*, 12, 190134–190157.
- Guo, F., et al. (2024). Information Security NIDS Based on ML. *IEEE ICDSNS*.
- Rahman, M. S., et al. (2024). Enhancing Cybersecurity with NIDS Using ML. *IEEE RAAICON*.
- Usuzaki, S., & Saito, R. (2024). An Architecture of NIDPS for Seamless Deployments. *IEEE GCCE*.

---

- **Developed by:** Muhammad Aiman Bin Noor Azmi (52215224160)
- **Supervisor:** Ts. Wan Hazimah Wan Ismail
- **Institution:** Universiti Kuala Lumpur, Malaysian Institute of Information Technology (UniKL MIIT)
'''

with open('/mnt/agents/output/README.md', 'w') as f:
    f.write(readme_content)

print("README.md saved successfully")
