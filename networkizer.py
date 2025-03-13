import scapy.all as scapy
import argparse

def packet_callback(packet):
    """Processes captured packets and displays relevant details."""
    print("\n📡 New Packet Captured:")
    
    if packet.haslayer(scapy.IP):
        print(f"🌍 Source IP: {packet[scapy.IP].src} → Destination IP: {packet[scapy.IP].dst}")
    
    if packet.haslayer(scapy.TCP):
        print(f"🔗 TCP Packet | Src Port: {packet[scapy.TCP].sport}, Dst Port: {packet[scapy.TCP].dport}")

    if packet.haslayer(scapy.UDP):
        print(f"📡 UDP Packet | Src Port: {packet[scapy.UDP].sport}, Dst Port: {packet[scapy.UDP].dport}")

    if packet.haslayer(scapy.ICMP):
        print("📶 ICMP Packet detected!")

    print(f"📦 Payload: {bytes(packet.payload)[:100]}...")

def start_sniffing(interface, protocol):
    """Starts capturing packets on the specified interface and protocol."""
    print(f"🔍 Sniffing on interface {interface}... Filtering for {protocol.upper()} packets.")
    
    filters = {
        "tcp": "tcp",
        "udp": "udp",
        "icmp": "icmp",
        "all": None
    }

    scapy.sniff(iface=interface, filter=filters.get(protocol, None), prn=packet_callback, store=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Packet Analysis Tool")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on (e.g., eth0, wlan0)")
    parser.add_argument("-p", "--protocol", choices=["tcp", "udp", "icmp", "all"], default="all", help="Protocol to filter (default: all)")

    args = parser.parse_args()
    start_sniffing(args.interface, args.protocol)
