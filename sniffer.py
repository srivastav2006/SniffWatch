#!/usr/bin/env python3
"""
Scapy-based packet sniffer (cross-platform) - Docker Enhanced
- Capture live traffic
- Parse Ethernet, IP/IPv6, TCP/UDP/ICMP
- Optional protocol filter (tcp/udp/icmp/ipv6) and BPF filter
- Save to .pcap
- Docker environment support
"""
import argparse
import datetime as dt
import sys
import os
from typing import Optional, List

try:
    from scapy.all import (
        sniff, wrpcap,
        conf, get_if_list,
        Ether, IP, IPv6, TCP, UDP, ICMP, Raw
    )
except Exception:
    print("Error: Scapy is required. Try: pip install scapy")
    raise

def human_ts() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def protocol_match(pkt, proto: Optional[str]) -> bool:
    if proto is None:
        return True
    proto = proto.lower()
    if proto == "tcp":
        return pkt.haslayer(TCP)
    if proto == "udp":
        return pkt.haslayer(UDP)
    if proto == "icmp":
        return pkt.haslayer(ICMP)
    if proto == "ipv6":
        return pkt.haslayer(IPv6)
    return True

def summarize(pkt) -> str:
    parts = []
    node_name = os.getenv('NODE_NAME', 'unknown')
    parts.append(f"[{node_name}]")

    # Link-layer (Ethernet)
    if Ether in pkt:
        eth = pkt[Ether]
        parts.append(f"ETH {eth.src}->{eth.dst} type=0x{eth.type:04x}")

    # Network-layer (IPv4/IPv6)
    if IP in pkt:
        ip = pkt[IP]
        parts.append(f"IP {ip.src}->{ip.dst} ttl={ip.ttl} proto={ip.proto}")
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        parts.append(f"IPv6 {ip6.src}->{ip6.dst} hlim={ip6.hlim}")

    # Transport-layer
    if TCP in pkt:
        tcp = pkt[TCP]
        parts.append(f"TCP {tcp.sport}->{tcp.dport} seq={tcp.seq} ack={tcp.ack} flags={tcp.flags}")
    elif UDP in pkt:
        udp = pkt[UDP]
        parts.append(f"UDP {udp.sport}->{udp.dport} len={udp.len}")
    elif ICMP in pkt:
        icmp = pkt[ICMP]
        parts.append(f"ICMP type={icmp.type} code={icmp.code}")

    # Payload length
    payload_len = len(pkt[Raw].load) if Raw in pkt else 0
    parts.append(f"payload={payload_len}B")

    return " | ".join(parts)

def list_interfaces():
    try:
        ifaces = get_if_list()
        print("Available interfaces:")
        for i, name in enumerate(ifaces, 1):
            print(f"  {i:02d}. {name}")
    except Exception as e:
        print("Could not list interfaces:", e)

def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer (Scapy) - Docker Enhanced")
    parser.add_argument("-i", "--iface", help="Interface name to sniff on (default: auto)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Packets to capture (0 = unlimited)")
    parser.add_argument("-p", "--proto", choices=["tcp","udp","icmp","ipv6"], help="Protocol filter")
    parser.add_argument("--bpf", help='BPF filter (e.g., "port 80" or "tcp and portrange 20-80")')
    parser.add_argument("--pcap", help="Write captured packets to this .pcap file")
    parser.add_argument("--list", action="store_true", help="List interfaces and exit")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (less verbose output)")

    args = parser.parse_args()

    if args.list:
        list_interfaces()
        sys.exit(0)

    # Create directories if they don't exist
    os.makedirs('/app/captures', exist_ok=True)
    os.makedirs('/app/logs', exist_ok=True)

    iface = args.iface or conf.iface  # default interface
    node_name = os.getenv('NODE_NAME', 'unknown')

    captured: List = []
    def on_packet(pkt):
        if not protocol_match(pkt, args.proto):
            return
        if args.pcap:
            captured.append(pkt)
        if not args.quiet:
            print(f"[{human_ts()}] {summarize(pkt)}")

    print(f"[*] {node_name} - Sniffing on interface: {iface}")
    if args.bpf:
        print(f"[*] BPF filter: {args.bpf}")
    if args.proto:
        print(f"[*] Protocol filter: {args.proto}")
    if args.count:
        print(f"[*] Packet limit: {args.count}")
    if args.pcap:
        print(f"[*] Writing to: {args.pcap}")

    try:
        sniff(
            iface=iface,
            prn=on_packet,
            filter=args.bpf,
            store=False,
            count=args.count if args.count > 0 else 0
        )
    except KeyboardInterrupt:
        print(f"\n[!] {node_name} - Stopped by user.")
    finally:
        if args.pcap and captured:
            try:
                wrpcap(args.pcap, captured)
                print(f"[+] {node_name} - Saved {len(captured)} packets to {args.pcap}")
            except Exception as e:
                print(f"[!] {node_name} - Failed to save pcap: {e}")

if __name__ == "__main__":
    main()
