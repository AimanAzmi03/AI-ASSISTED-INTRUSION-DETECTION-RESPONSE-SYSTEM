#!/usr/bin/env python3
"""
IDRS - Real-Time ML Anomaly Detector using Isolation Forest
Extracts CICIDS2017-compatible flow features from live packets
"""

import numpy as np
import joblib
import json
import time
from collections import defaultdict, deque


class FlowFeatureExtractor:
    def __init__(self, flow_timeout=120):
        self.flow_timeout = flow_timeout
        self.flows = {}
        self.completed_flows = deque(maxlen=500)

    def get_flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        return (dst_ip, src_ip, dst_port, src_port, protocol)

    def process_packet(self, pkt):
        from scapy.all import IP, TCP, UDP

        if not pkt.haslayer(IP):
            return None

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = 'TCP' if pkt.haslayer(TCP) else 'UDP' if pkt.haslayer(UDP) else 'OTHER'
        src_port = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport if pkt.haslayer(UDP) else 0
        dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else 0

        flow_key = self.get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        now = time.time()

        if flow_key in self.flows:
            flow = self.flows[flow_key]
            if now - flow['last_seen'] > self.flow_timeout:
                self.finalize_flow(flow_key)
                self.flows[flow_key] = self._new_flow(src_ip, dst_ip, src_port, dst_port, protocol, now)
            else:
                self._update_flow(flow, pkt, now, src_ip)
        else:
            self.flows[flow_key] = self._new_flow(src_ip, dst_ip, src_port, dst_port, protocol, now)

        return flow_key

    def _new_flow(self, src_ip, dst_ip, src_port, dst_port, protocol, now):
        return {
            'src_ip': src_ip, 'dst_ip': dst_ip, 'src_port': src_port, 'dst_port': dst_port,
            'protocol': protocol, 'start_time': now, 'last_seen': now,
            'fwd_packets': 1, 'bwd_packets': 0, 'fwd_bytes': 0, 'bwd_bytes': 0,
            'fwd_pkt_lengths': [], 'bwd_pkt_lengths': [],
            'iat_times': [0], 'fwd_iat': [0], 'bwd_iat': [0],
            'last_fwd_time': now, 'last_bwd_time': now,
            'fwd_psh': 0, 'bwd_psh': 0, 'fwd_urg': 0, 'bwd_urg': 0,
            'fwd_hdr': 0, 'bwd_hdr': 0,
            'fin': 0, 'syn': 0, 'rst': 0, 'psh': 0, 'ack': 0, 'urg': 0,
            'cwe': 0, 'ece': 0,
            'min_len': float('inf'), 'max_len': 0,
            'fwd_bulk_bytes': 0, 'bwd_bulk_bytes': 0,
            'fwd_bulk_packets': 0, 'bwd_bulk_packets': 0,
            'fwd_subflow_pkts': 0, 'fwd_subflow_bytes': 0,
            'bwd_subflow_pkts': 0, 'bwd_subflow_bytes': 0,
            'init_win_fwd': 0, 'init_win_bwd': 0,
            'act_data_pkt_fwd': 0, 'min_seg_size_fwd': 0
        }

    def _update_flow(self, flow, pkt, now, src_ip):
        from scapy.all import TCP, UDP

        pkt_len = len(pkt)
        is_fwd = (src_ip == flow['src_ip'])
        flow['last_seen'] = now

        if is_fwd:
            flow['fwd_packets'] += 1
            flow['fwd_bytes'] += pkt_len
            flow['fwd_pkt_lengths'].append(pkt_len)
            flow['fwd_iat'].append(now - flow['last_fwd_time'])
            flow['last_fwd_time'] = now
            if pkt.haslayer(TCP):
                flags = int(pkt[TCP].flags)
                flow['fwd_psh'] += 1 if flags & 0x08 else 0
                flow['fwd_urg'] += 1 if flags & 0x20 else 0
                flow['fwd_hdr'] += pkt[TCP].dataofs * 4 if hasattr(pkt[TCP], 'dataofs') else 20
                flow['fin'] += 1 if flags & 0x01 else 0
                flow['syn'] += 1 if flags & 0x02 else 0
                flow['rst'] += 1 if flags & 0x04 else 0
                flow['psh'] += 1 if flags & 0x08 else 0
                flow['ack'] += 1 if flags & 0x10 else 0
                flow['urg'] += 1 if flags & 0x20 else 0
                flow['ece'] += 1 if flags & 0x40 else 0
                flow['cwe'] += 1 if flags & 0x80 else 0
                
                # Window size (init_win_fwd)
                if flow['fwd_packets'] == 1:
                    flow['init_win_fwd'] = pkt[TCP].window
        else:
            flow['bwd_packets'] += 1
            flow['bwd_bytes'] += pkt_len
            flow['bwd_pkt_lengths'].append(pkt_len)
            flow['bwd_iat'].append(now - flow['last_bwd_time'])
            flow['last_bwd_time'] = now
            if pkt.haslayer(TCP):
                flags = int(pkt[TCP].flags)
                flow['bwd_psh'] += 1 if flags & 0x08 else 0
                flow['bwd_urg'] += 1 if flags & 0x20 else 0
                flow['bwd_hdr'] += pkt[TCP].dataofs * 4 if hasattr(pkt[TCP], 'dataofs') else 20
                
                # Window size (init_win_bwd)
                if flow['bwd_packets'] == 1:
                    flow['init_win_bwd'] = pkt[TCP].window

        flow['iat_times'].append(now - flow['last_seen'])
        flow['min_len'] = min(flow['min_len'], pkt_len)
        flow['max_len'] = max(flow['max_len'], pkt_len)

    def finalize_flow(self, flow_key):
        if flow_key not in self.flows:
            return None

        flow = self.flows.pop(flow_key)
        dur_sec = max(flow['last_seen'] - flow['start_time'], 0.000001)
        dur_us = dur_sec * 1000000
        total_pkt = flow['fwd_packets'] + flow['bwd_packets']
        total_bytes = flow['fwd_bytes'] + flow['bwd_bytes']

        if total_pkt == 0:
            return None

        all_lengths = flow['fwd_pkt_lengths'] + flow['bwd_pkt_lengths']
        fwd_len = flow['fwd_pkt_lengths']
        bwd_len = flow['bwd_pkt_lengths']

        # Helper for safe stats
        def safe_mean(arr):
            return np.mean(arr) if arr else 0
        def safe_std(arr):
            return np.std(arr) if len(arr) > 1 else 0
        def safe_max(arr):
            return max(arr) if arr else 0
        def safe_min(arr):
            return min(arr) if arr else 0

        # Calculate all 68 CICIDS2017 features
        features = {
            # Basic flow features (1-7)
            'Flow Duration': dur_us,
            'Total Fwd Packets': flow['fwd_packets'],
            'Total Backward Packets': flow['bwd_packets'],
            'Total Length of Fwd Packets': flow['fwd_bytes'],
            'Total Length of Bwd Packets': flow['bwd_bytes'],
            
            # Packet length features (8-13)
            'Fwd Packet Length Max': safe_max(fwd_len),
            'Fwd Packet Length Min': safe_min(fwd_len),
            'Fwd Packet Length Mean': safe_mean(fwd_len),
            'Fwd Packet Length Std': safe_std(fwd_len),
            'Bwd Packet Length Max': safe_max(bwd_len),
            'Bwd Packet Length Min': safe_min(bwd_len),
            'Bwd Packet Length Mean': safe_mean(bwd_len),
            'Bwd Packet Length Std': safe_std(bwd_len),
            
            # Flow rate features (14-16)
            'Flow Bytes/s': total_bytes / dur_sec,
            'Flow Packets/s': total_pkt / dur_sec,
            
            # IAT features (17-24)
            'Flow IAT Mean': safe_mean(flow['iat_times']),
            'Flow IAT Std': safe_std(flow['iat_times']),
            'Flow IAT Max': safe_max(flow['iat_times']),
            'Flow IAT Min': safe_min(flow['iat_times']),
            'Fwd IAT Total': sum(flow['fwd_iat']) if flow['fwd_iat'] else 0,
            'Fwd IAT Mean': safe_mean(flow['fwd_iat']),
            'Fwd IAT Std': safe_std(flow['fwd_iat']),
            'Fwd IAT Max': safe_max(flow['fwd_iat']),
            'Fwd IAT Min': safe_min(flow['fwd_iat']),
            'Bwd IAT Total': sum(flow['bwd_iat']) if flow['bwd_iat'] else 0,
            'Bwd IAT Mean': safe_mean(flow['bwd_iat']),
            'Bwd IAT Std': safe_std(flow['bwd_iat']),
            'Bwd IAT Max': safe_max(flow['bwd_iat']),
            'Bwd IAT Min': safe_min(flow['bwd_iat']),
            
            # Flag features (25-32)
            'Fwd PSH Flags': flow['fwd_psh'],
            'Bwd PSH Flags': flow['bwd_psh'],
            'Fwd URG Flags': flow['fwd_urg'],
            'Bwd URG Flags': flow['bwd_urg'],
            'Fwd Header Length': flow['fwd_hdr'],
            'Bwd Header Length': flow['bwd_hdr'],
            'Fwd Packets/s': flow['fwd_packets'] / dur_sec,
            'Bwd Packets/s': flow['bwd_packets'] / dur_sec,
            
            # Packet length stats (33-38)
            'Min Packet Length': flow['min_len'] if flow['min_len'] != float('inf') else 0,
            'Max Packet Length': flow['max_len'],
            'Packet Length Mean': safe_mean(all_lengths),
            'Packet Length Std': safe_std(all_lengths),
            'Packet Length Variance': np.var(all_lengths) if len(all_lengths) > 1 else 0,
            
            # TCP flag counts (39-44)
            'FIN Flag Count': flow['fin'],
            'SYN Flag Count': flow['syn'],
            'RST Flag Count': flow['rst'],
            'PSH Flag Count': flow['psh'],
            'ACK Flag Count': flow['ack'],
            'URG Flag Count': flow['urg'],
            
            # Additional flags (45-46)
            'CWE Flag Count': flow['cwe'],
            'ECE Flag Count': flow['ece'],
            
            # Ratio features (47-52)
            'Down/Up Ratio': flow['bwd_packets'] / (flow['fwd_packets'] + 0.001),
            'Average Packet Size': total_bytes / total_pkt,
            'Avg Fwd Segment Size': flow['fwd_bytes'] / (flow['fwd_packets'] + 0.001),
            'Avg Bwd Segment Size': flow['bwd_bytes'] / (flow['bwd_packets'] + 0.001),
            
            # Subflow features (53-56)
            'Subflow Fwd Packets': flow['fwd_packets'],
            'Subflow Fwd Bytes': flow['fwd_bytes'],
            'Subflow Bwd Packets': flow['bwd_packets'],
            'Subflow Bwd Bytes': flow['bwd_bytes'],
            
            # Window/features (57-62)
            'Init_Win_bytes_forward': flow['init_win_fwd'],
            'Init_Win_bytes_backward': flow['init_win_bwd'],
            'act_data_pkt_fwd': flow['fwd_packets'],
            'min_seg_size_forward': safe_min(fwd_len),
            
            # Extra ratio features to reach 68
            'Active Mean': 0,  # Not tracked in basic flow
            'Active Std': 0,
            'Active Max': 0,
            'Active Min': 0,
            'Idle Mean': 0,
            'Idle Std': 0,
            'Idle Max': 0,
            'Idle Min': 0
        }

        flow['features'] = features
        self.completed_flows.append(flow)
        return flow

    def get_all_flows(self):
        current = time.time()
        old = [k for k, v in self.flows.items() if current - v['last_seen'] > self.flow_timeout]
        for k in old:
            self.finalize_flow(k)
        return list(self.completed_flows)

    def cleanup_old_flows(self):
        self.get_all_flows()


class MLAnomalyDetector:
    def __init__(self, model_path='./models/idrs_if_model.pkl',
                 scaler_path='./models/idrs_scaler.pkl',
                 selector_path='./models/idrs_selector.pkl',
                 features_path='./models/idrs_features.json'):

        print("[*] Loading ML models...")
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.selector = joblib.load(selector_path)

        with open(features_path, 'r') as f:
            meta = json.load(f)
            self.feature_names = meta['features']

        self.extractor = FlowFeatureExtractor()
        self.threshold = 0.1798  # UPDATED from training results
        print(f"[+] ML Detector ready ({len(self.feature_names)} features, threshold={self.threshold})")

    def process_packet(self, pkt):
        self.extractor.process_packet(pkt)

    def get_and_check_flows(self):
        flows = self.extractor.get_all_flows()
        results = []

        for flow in flows:
            if 'features' not in flow:
                continue

            try:
                # Extract features in EXACT order expected by model
                vec = []
                for feat_name in self.feature_names:
                    val = flow['features'].get(feat_name, 0)
                    # Handle inf/nan
                    if np.isinf(val) or np.isnan(val):
                        val = 0
                    vec.append(float(val))
                
                X = np.array(vec).reshape(1, -1)
                
                # Debug: check feature count
                if X.shape[1] != len(self.feature_names):
                    print(f"[ML WARN] Feature mismatch: got {X.shape[1]}, expected {len(self.feature_names)}")
                    continue
                
                X_scaled = self.scaler.transform(X)
                X_sel = self.selector.transform(X_scaled)

                pred = self.model.predict(X_sel)[0]
                score = self.model.decision_function(X_sel)[0]

                if pred == -1 and score < self.threshold:
                    results.append({
                        'src_ip': flow['src_ip'],
                        'dst_ip': flow['dst_ip'],
                        'score': float(score),
                        'flow_key': flow.get('flow_key')
                    })
            except Exception as e:
                print(f"[ML PREDICT ERROR] {e}")

        return results

    def cleanup_old_flows(self):
        self.extractor.get_all_flows()


if __name__ == "__main__":
    detector = MLAnomalyDetector()
    print("[+] ML module test successful")