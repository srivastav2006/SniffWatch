#!/usr/bin/env python3
"""
Raw-socket packet sniffer (Linux-only)
- Uses AF_PACKET and SOCK_RAW
- Parses Ethernet, IPv4, TCP/UDP headers (summary)
"""
import socket
import struct
import datetime as dt

ETH_P_ALL = 0x0003  # all protocols

def human_ts():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def mac_addr(b):
    return ':'.join(f'{x:02x}' for x in b)

def ipv4(addr):
    return '.'.join(map(str, addr))

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    print("[*] Raw socket sniffer started (Linux only). Ctrl+C to stop.")
    while True:
        try:
            raw_data, _ = s.recvfrom(65535)

            # Ethernet header: 14 bytes
            if len(raw_data) < 14:
                continue
            dst, src, proto = struct.unpack('!6s6sH', raw_data[0:14])
            offset = 14

            # IPv4
            if proto == 0x0800 and len(raw_data) >= offset + 20:
                iph = struct.unpack('!BBHHHBBH4s4s', raw_data[offset:offset+20])
                ver_ihl = iph[0]
                ihl = (ver_ihl & 0x0F) * 4
                total_len = iph[2]
                proto_id = iph[6]
                src_ip = ipv4(iph[8])
                dst_ip = ipv4(iph[9])
                offset += ihl

                summary = [f"ETH {mac_addr(src)}->{mac_addr(dst)} type=0x0800",
                           f"IP {src_ip}->{dst_ip} len={total_len} proto={proto_id}"]

                # TCP
                if proto_id == 6 and len(raw_data) >= offset + 20:
                    tcph = struct.unpack('!HHLLHHHH', raw_data[offset:offset+20])
                    sport, dport, seq, ack, data_offset_reserved_flags, _, _, _ = tcph
                    data_offset = ((data_offset_reserved_flags >> 12) & 0xF) * 4
                    flags = data_offset_reserved_flags & 0x01FF  # 9 bits
                    offset += data_offset
                    payload_len = max(0, len(raw_data) - offset)
                    summary.append(f"TCP {sport}->{dport} flags=0x{flags:03x} payload={payload_len}B")

                # UDP
                elif proto_id == 17 and len(raw_data) >= offset + 8:
                    udph = struct.unpack('!HHHH', raw_data[offset:offset+8])
                    sport, dport, length, _ = udph
                    offset += 8
                    payload_len = max(0, len(raw_data) - offset)
                    summary.append(f"UDP {sport}->{dport} len={length} payload={payload_len}B")

                print(f"[{human_ts()}] " + " | ".join(summary))

        except KeyboardInterrupt:
            print("\n[!] Stopped by user.")
            break

if __name__ == '__main__':
    main()
