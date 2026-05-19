#!/usr/bin/env python3
"""
IDRS - Integrated Rule-Based + ML Anomaly Detection
Sniffs on enp0s3 (Host-Only adapter with Promiscuous Mode)
"""

import json
import sys
import time
import sqlite3
import threading
import queue
import subprocess
import os
import shutil
from datetime import datetime, timedelta
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not available")

try:
    from ml_detector import MLAnomalyDetector
    ML_AVAILABLE = True
except Exception as e:
    print(f"[!] ML module not available: {e}")
    ML_AVAILABLE = False

# Load config if exists
try:
    with open('config.json', 'r') as f:
        config = json.load(f)
except FileNotFoundError:
    config = {}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "idrs.db")

# ==================== YOUR VM TOPOLOGY ====================
IDS_IP = "192.168.56.103"
ATTACKER_IP = "192.168.56.101"
VICTIM_IP = "192.168.56.102"
# =========================================================

TRUSTED_IPS = [IDS_IP, VICTIM_IP, "192.168.56.1", "127.0.0.1"]

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            threat TEXT NOT NULL,
            attacker_ip TEXT NOT NULL,
            victim_ip TEXT NOT NULL,
            details TEXT,
            detection_type TEXT DEFAULT 'rule',
            ml_score REAL,
            status TEXT DEFAULT 'active'
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            threat_type TEXT NOT NULL,
            blocked_at TEXT NOT NULL,
            expires_at TEXT,
            block_count INTEGER DEFAULT 1,
            status TEXT DEFAULT 'active',
            detection_source TEXT DEFAULT 'rule'
        )
    """)

    conn.commit()
    conn.close()


init_db()

PREVENTION_CONFIG = {
    'enabled': True,
    'block_duration_minutes': 30,
    'dos_block_threshold': 100,
    'scan_block_threshold': 10,
    'max_block_count': 3,
    'whitelist': [
        '127.0.0.1',
        IDS_IP,              # NEVER BLOCK THE IDS ITSELF
        '192.168.56.1',      # VirtualBox host gateway
        '0.0.0.0',           # DHCP discovery source
        config.get('gateway_ip', '')
    ]
}

tracker = defaultdict(lambda: {
    "ports": set(),
    "count": 0,
    "start_time": time.time(),
    "blocked": False
})
WINDOW_SIZE = 10

alert_queue = queue.Queue()
block_queue = queue.Queue()
ml_alert_queue = queue.Queue()

ml_detector = None
if ML_AVAILABLE:
    try:
        ml_detector = MLAnomalyDetector()
        print("[*] ML Anomaly Detector loaded successfully")
    except Exception as e:
        print(f"[!] Failed to load ML model: {e}")
        ML_AVAILABLE = False


def is_whitelisted(ip):
    if not ip or ip in ['0.0.0.0', '::', '']:
        return True
    if ip in PREVENTION_CONFIG['whitelist']:
        return True
    if ip in TRUSTED_IPS:          # <-- NEVER block your own machines
        return True
    if ip.startswith('127.'):
        return True
    if ip.startswith('224.') or ip.startswith('239.') or ip == '255.255.255.255':
        return True
    return False


def run_iptables(cmd):
    """Run iptables with sudo if available, otherwise fallback to direct."""
    sudo_path = shutil.which("sudo")
    full_cmd = f"{sudo_path} {cmd}" if sudo_path else cmd
    return subprocess.run(full_cmd, shell=True, capture_output=True, text=True)

def add_iptables_rule(ip, threat_type, source='rule'):
    try:
        # Check if rule already exists (-w 5 waits for lock)
        check = run_iptables(f"iptables -w 5 -C INPUT -s {ip} -j DROP")
        if check.returncode == 0:
            print(f"[PREVENTION] Rule for {ip} already exists")
            return False

        # Add DROP rule to INPUT and FORWARD
        result_input = run_iptables(f"iptables -w 5 -I INPUT 1 -s {ip} -j DROP")
        if result_input.returncode != 0:
            print(f"[PREVENTION] INPUT rule failed for {ip}: {result_input.stderr.strip()}")
            return False

        result_fwd = run_iptables(f"iptables -w 5 -I FORWARD 1 -s {ip} -j DROP")
        if result_fwd.returncode != 0:
            print(f"[PREVENTION] FORWARD rule failed for {ip}: {result_fwd.stderr.strip()}")
            return False

        print(f"[PREVENTION] BLOCKED {ip} ({threat_type}) [source: {source}]")
        return True

    except Exception as e:
        print(f"[PREVENTION] Exception blocking {ip}: {e}")
        return False


def remove_iptables_rule(ip):
    try:
        # Remove from both chains, ignore errors if rule doesn't exist
        run_iptables(f"iptables -w 5 -D INPUT -s {ip} -j DROP")
        run_iptables(f"iptables -w 5 -D FORWARD -s {ip} -j DROP")
        print(f"[PREVENTION] Unblocked {ip}")
        return True
    except Exception as e:
        print(f"[PREVENTION] Exception unblocking {ip}: {e}")
        return False


def get_block_duration(ip):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT block_count FROM blocked_ips WHERE ip_address = ?", (ip,))
    result = cur.fetchone()
    conn.close()

    if result:
        count = result[0]
        if count >= PREVENTION_CONFIG['max_block_count']:
            return None
        return PREVENTION_CONFIG['block_duration_minutes'] * count
    return PREVENTION_CONFIG['block_duration_minutes']


def record_block(ip, threat_type, duration_minutes, source='rule'):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    blocked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    expires_at = (datetime.now() + timedelta(minutes=duration_minutes)).strftime("%Y-%m-%d %H:%M:%S") if duration_minutes else None

    try:
        cur.execute("""
            INSERT INTO blocked_ips (ip_address, threat_type, blocked_at, expires_at, block_count, status, detection_source)
            VALUES (?, ?, ?, ?, 1, 'active', ?)
        """, (ip, threat_type, blocked_at, expires_at, source))
    except sqlite3.IntegrityError:
        cur.execute("""
            UPDATE blocked_ips 
            SET threat_type = ?, blocked_at = ?, expires_at = ?, 
                block_count = block_count + 1, status = 'active', detection_source = ?
            WHERE ip_address = ?
        """, (threat_type, blocked_at, expires_at, source, ip))

    conn.commit()
    conn.close()


def should_block(threat_type, metric):
    if not PREVENTION_CONFIG['enabled']:
        return False
    if threat_type == "DoS Flood":
        return metric >= PREVENTION_CONFIG['dos_block_threshold']
    if threat_type == "Port Scan":
        return metric >= PREVENTION_CONFIG['scan_block_threshold']
    if threat_type == "ML Anomaly":
        return True
    return False


def db_writer():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    while True:
        alert = alert_queue.get()
        try:
            cur.execute("""
                INSERT INTO alerts (timestamp, threat, attacker_ip, victim_ip, details, detection_type, ml_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, alert)
            conn.commit()
        except Exception as e:
            print(f"[DB ERROR] {e}")
        alert_queue.task_done()


def ml_db_writer():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    while True:
        alert = ml_alert_queue.get()
        try:
            cur.execute("""
                INSERT INTO alerts (timestamp, threat, attacker_ip, victim_ip, details, detection_type, ml_score)
                VALUES (?, ?, ?, ?, ?, 'ml', ?)
            """, alert)
            conn.commit()
        except Exception as e:
            print(f"[ML DB ERROR] {e}")
        ml_alert_queue.task_done()


def block_executor():
    while True:
        ip, threat, source = block_queue.get()

        if is_whitelisted(ip):
            print(f"[PREVENTION] SKIP {ip} - whitelisted")
            block_queue.task_done()
            continue

        duration = get_block_duration(ip)
        if add_iptables_rule(ip, threat, source):
            record_block(ip, threat, duration, source)
            if duration:
                threading.Timer(duration * 60, auto_unblock, args=[ip]).start()

        block_queue.task_done()


def auto_unblock(ip):
    remove_iptables_rule(ip)
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("UPDATE blocked_ips SET status = 'expired' WHERE ip_address = ?", (ip,))
    conn.commit()
    conn.close()
    print(f"[PREVENTION] Auto-unblocked {ip}")


def ml_detection_loop():
    if not ml_detector:
        return

    print("[*] ML detection thread started")
    while True:
        time.sleep(5)
        try:
            anomalies = ml_detector.get_and_check_flows()
            for anomaly in anomalies:
                src = anomaly['src_ip']
                dst = anomaly['dst_ip']
                score = anomaly['score']

                if tracker[src]["blocked"]:
                    continue

                print(f"[ML] ANOMALY: {src} -> {dst} (score: {score:.4f})")
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                ml_alert_queue.put((ts, "ML Anomaly", src, dst, f"Score: {score:.4f}", score))

                if score < 0.18:
                    tracker[src]["blocked"] = True
                    block_queue.put((src, "ML Anomaly", 'ml'))

            ml_detector.cleanup_old_flows()
        except Exception as e:
            print(f"[ML ERROR] {e}")


def queue_alert_and_block(threat, attacker, victim, details, metric):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    alert_queue.put((ts, threat, attacker, victim, details, 'rule', None))
    print(f"[RULE] {threat}: {attacker} -> {victim}")

    if should_block(threat, metric) and not tracker[attacker]["blocked"]:
        tracker[attacker]["blocked"] = True
        block_queue.put((attacker, threat, 'rule'))


def analyze_packet(pkt):
    if not SCAPY_AVAILABLE or not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    
    # === FALSE POSITIVE FILTER ===
    # Skip broadcast, multicast, and link-local traffic
    if (dst.startswith('224.') or 
        dst.startswith('239.') or 
        dst == '255.255.255.255' or
        dst.startswith('ff02::') or
        src == '0.0.0.0' or
        src.startswith('169.254.')):
        return
    # =============================

    if ml_detector:
        ml_detector.process_packet(pkt)

    if tracker[src]["blocked"]:
        return

    if is_whitelisted(src):
        return

    now = time.time()

    if now - tracker[src]["start_time"] > WINDOW_SIZE:
        tracker[src] = {"ports": set(), "count": 0, "start_time": now, "blocked": False}

    tracker[src]["count"] += 1

    if tracker[src]["count"] > config.get('dos_threshold', 100):
        queue_alert_and_block("DoS Flood", src, dst,
            f"Packets: {tracker[src]['count']}", tracker[src]["count"])

    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        dport = pkt.dport
        tracker[src]["ports"].add(dport)
        if len(tracker[src]["ports"]) > config.get('scan_threshold', 10):
            queue_alert_and_block("Port Scan", src, dst,
                f"Ports: {len(tracker[src]['ports'])}", len(tracker[src]["ports"]))


if __name__ == "__main__":
    # HARDCODED: Use enp0s3 (Host-Only adapter)
    sniff_iface = 'enp0s3'
    
    # Verify interface exists
    if SCAPY_AVAILABLE:
        available = get_if_list()
        if sniff_iface not in available:
            print(f"[!] Interface '{sniff_iface}' not found!")
            print(f"[*] Available interfaces: {available}")
            print("[!] Check 'ip addr' and update sniff_iface variable")
            sys.exit(1)

    threading.Thread(target=db_writer, daemon=True).start()
    threading.Thread(target=ml_db_writer, daemon=True).start()
    threading.Thread(target=block_executor, daemon=True).start()

    if ML_AVAILABLE and ml_detector:
        threading.Thread(target=ml_detection_loop, daemon=True).start()

    print("="*60)
    print("IDRS - Rule + ML Detection Engine")
    print("="*60)
    print(f"[*] IDS VM:      {IDS_IP}")
    print(f"[*] Attacker VM: {ATTACKER_IP}")
    print(f"[*] Victim VM:   {VICTIM_IP}")
    print(f"[*] Rule Engine: ENABLED")
    print(f"[*] ML Engine:   {'ENABLED' if ML_AVAILABLE else 'DISABLED'}")
    print(f"[*] Interface:   {sniff_iface}")
    print(f"[*] Prevention:  {'ENABLED' if PREVENTION_CONFIG['enabled'] else 'DISABLED'}")
    print(f"[*] Whitelisted: {PREVENTION_CONFIG['whitelist']}")
    print("="*60)
    print("[*] IMPORTANT: Enable promiscuous mode before starting:")
    print(f"    sudo ip link set {sniff_iface} promisc on")
    print("[*] Also enable in VirtualBox: Settings > Network > Advanced > Promiscuous Mode: Allow All")
    print("="*60)

    try:
        sniff(iface=sniff_iface, filter="ip", prn=analyze_packet, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping IDS...")