#!/usr/bin/env python3
"""
Basic IDS on top of Scapy capture (separate from sniffer.py)
- Detects:
  * Port scan: many unique destination ports from same source within a window
  * Flood: too many packets from same source within a window
- Tunable thresholds via CLI args
"""
import argparse
import time
from collections import defaultdict, deque

from scapy.all import sniff, conf, IP, TCP, UDP

def main():
    parser = argparse.ArgumentParser(description="Basic IDS (port scan + flood detection)")
    parser.add_argument("-i", "--iface", help="Interface to sniff on (default: auto)")
    parser.add_argument("--bpf", help='BPF filter (e.g., "tcp or udp")')
    parser.add_argument("-c", "--count", type=int, default=0, help="Packets to capture (0 = unlimited)")
    parser.add_argument("--window", type=int, default=10, help="Sliding window in seconds (default: 10)")
    parser.add_argument("--port-threshold", type=int, default=20, help="Unique dest ports threshold (default: 20)")
    parser.add_argument("--flood-threshold", type=int, default=100, help="Packets per window threshold (default: 100)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Less verbose (print only alerts)")

    args = parser.parse_args()

    iface = args.iface or conf.iface

    # For flood detection: map src_ip -> deque[timestamps]
    pkt_times = defaultdict(deque)

    # For port scan: map src_ip -> (timestamped ports in window)
    # We'll maintain a deque of (timestamp, dport) and a set for quick uniqueness.
    port_deques = defaultdict(deque)
    port_sets = defaultdict(set)

    window = args.window
    port_thresh = args.port_threshold
    flood_thresh = args.flood_threshold

    def purge_old(ip, now):
        # purge old timestamps from pkt_times
        dq = pkt_times[ip]
        while dq and now - dq[0] > window:
            dq.popleft()

        # purge old (ts, dport) from port_deques + keep set in sync
        pdq = port_deques[ip]
        changed = False
        while pdq and now - pdq[0][0] > window:
            _, old_port = pdq.popleft()
            # rebuild the set if necessary (small overhead, keeps correctness)
            changed = True
        if changed:
            port_sets[ip] = {p for (_, p) in pdq}

    def on_packet(pkt):
        if IP not in pkt:
            return

        now = time.time()
        src = pkt[IP].src
        dst = pkt[IP].dst

        # ---- FLOOD detection (packets per window) ----
        pkt_times[src].append(now)
        purge_old(src, now)
        if len(pkt_times[src]) > flood_thresh:
            print(f"[ALERT][FLOOD] {src} -> *  : {len(pkt_times[src])} packets/{window}s")

        # ---- PORT SCAN detection (unique dest ports per window) ----
        dport = None
        if TCP in pkt:
            dport = pkt[TCP].dport
        elif UDP in pkt:
            dport = pkt[UDP].dport

        if dport is not None:
            port_deques[src].append((now, dport))
            # purge old + sync set
            purge_old(src, now)
            # ensure set includes latest dport
            if dport not in port_sets[src]:
                port_sets[src].add(dport)

            if len(port_sets[src]) > port_thresh:
                print(f"[ALERT][PORT-SCAN] {src} -> many ports ({len(port_sets[src])}) in {window}s")

        if not args.quiet:
            proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else f"IP({pkt[IP].proto})"
            base = f"{time.strftime('%H:%M:%S')} Packet: {src} -> {dst} [{proto}]"
            if dport is not None:
                base += f" dport={dport}"
            print(base)

    print(f"[*] IDS on interface: {iface}")
    if args.bpf:
        print(f"[*] BPF filter: {args.bpf}")
    print(f"[*] Window={window}s | Port-threshold={port_thresh} | Flood-threshold={flood_thresh}")

    try:
        sniff(
            iface=iface,
            prn=on_packet,
            filter=args.bpf,
            store=False,
            count=args.count if args.count > 0 else 0
        )
    except KeyboardInterrupt:
        print("\n[!] IDS stopped by user.")

if __name__ == "__main__":
    main()
