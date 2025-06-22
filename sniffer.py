from scapy.all import sniff, IP
from db import insert_packet
from alert import detect_anomalies
import time

print("Sniffer started... waiting for packets.")  # 👈 added line

def handle_packet(pkt):
    if pkt.haslayer(IP):
        ts = time.time()
        src = pkt[IP].src
        dst = pkt[IP].dst
        length = len(pkt)

        sport = pkt.sport if hasattr(pkt, 'sport') else 0
        dport = pkt.dport if hasattr(pkt, 'dport') else 0
        proto = pkt.sprintf('%IP.proto%')

        insert_packet(ts, src, dst, sport, dport, proto, length)
        print(f"[+] {src} -> {dst} | Proto: {proto} | Len: {length}")
        print(pkt.summary())  # 👈 helps debug

        if proto in ['tcp', 'udp']:
            detect_anomalies(src, dport)

# 👇 use loopback interface to capture localhost traffic
sniff(iface="lo", filter="ip", prn=handle_packet, store=False)



