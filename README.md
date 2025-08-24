# Packet Sniffer + Basic IDS (Python)

A clean, beginner-friendly **packet sniffer** using **Scapy**, plus a **separate basic IDS** script that detects
simple suspicious behaviors (port scans and packet floods). Includes a Linux-only raw-socket demo.

## Features
- Sniffer (cross-platform via Scapy)
  - Parse Ethernet → IP/IPv6 → TCP/UDP/ICMP
  - Optional protocol filter and BPF filter (e.g., "port 80")
  - Save captures to **.pcap** (open in Wireshark)
- IDS (separate script)
  - **Port Scan detection**: many distinct destination ports from same source in a time window
  - **Flood detection**: too many packets from same source in a time window
  - Tunable thresholds via CLI args
- Raw socket demo (Linux only) for low-level learning

## Quick Start

### 1) Create venv and install
```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
# .venv\Scripts\activate

pip install -r requirements.txt
Windows users: Install Npcap first (Scapy uses it under the hood).
```

### 2) List interfaces (optional)
```bash

python sniffer.py --list
```
### 3) Run the sniffer
```bash

# auto-picks default interface
sudo python sniffer.py

# choose interface
sudo python sniffer.py -i eth0

# only TCP + BPF (port 80)
sudo python sniffer.py -p tcp --bpf "port 80"

# save to pcap
sudo python sniffer.py --pcap capture.pcap
```
### 4) Run the IDS (suspicious detection)
```bash

# defaults: window=10s, port-scan threshold=20 unique ports, flood=100 pkts/10s
sudo python sniffer_ids.py -i eth0

# tweak thresholds/window
sudo python sniffer_ids.py -i eth0 --window 15 --port-threshold 30 --flood-threshold 200

# add a BPF filter (optional)
sudo python sniffer_ids.py -i eth0 --bpf "tcp"
```
### 5) Linux raw-socket demo (optional)
```bash

sudo python raw_sniffer_linux.py
```
### Project Structure
```graphql

packet-sniffer/
├─ sniffer.py               # Scapy-based sniffer (cross-platform)
├─ sniffer_ids.py           # Basic IDS: port scan + flood detection (separate)
├─ raw_sniffer_linux.py     # Raw socket Linux-only demo
├─ requirements.txt
└─ README.md
