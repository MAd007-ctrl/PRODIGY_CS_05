from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import threading
import os

# File to log captured packet data
LOG_FILE = "packet_logs.txt"

# Protocol Mapping
protocol_map = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

# Clear old logs if exist
if os.path.exists(LOG_FILE):
    os.remove(LOG_FILE)

def log_packet(data: str):
    """Log packet details to a file."""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(data + "\n" + "-" * 80 + "\n")

def packet_callback(packet):
    """Callback for every captured packet."""
    if IP in packet:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        protocol_name = protocol_map.get(protocol, 'Other')
        payload = ""
        ports = ""

        # TCP/UDP Port Info
        if TCP in packet:
            ports = f"TCP Src Port: {packet[TCP].sport} → Dst Port: {packet[TCP].dport}"
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                protocol_name = "HTTP"
        elif UDP in packet:
            ports = f"UDP Src Port: {packet[UDP].sport} → Dst Port: {packet[UDP].dport}"
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                protocol_name = "DNS"

        if ICMP in packet:
            protocol_name = "ICMP"

        # Extract readable payload (if any)
        if Raw in packet:
            try:
                payload = packet[Raw].load.decode(errors="ignore")[:100]
            except:
                payload = "<Non-decodable payload>"

        output = (
            f"Timestamp   : {timestamp}\n"
            f"Source IP   : {src_ip}\n"
            f"Destination : {dst_ip}\n"
            f"Protocol    : {protocol_name}\n"
            f"{ports}\n"
            f"Payload     : {payload}"
        )

        print(output)
        log_packet(output)

def start_sniffer(interface=None):
    """Start sniffing packets on the given network interface."""
    print("🚀 Starting Advanced Packet Capture... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=packet_callback, store=False)

def run_sniffer():
    try:
        interface = input("Enter interface to sniff (leave blank for all): ").strip() or None
        sniff_thread = threading.Thread(target=start_sniffer, args=(interface,), daemon=True)
        sniff_thread.start()

        while sniff_thread.is_alive():
            sniff_thread.join(1)
    except KeyboardInterrupt:
        print("\n📴 Packet capture stopped by user.")
        print(f"📁 Logs saved in: {LOG_FILE}")

if __name__ == "__main__":
    run_sniffer()
