# Import necessary libraries
from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Extract IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # Determine the protocol type
        if protocol == 6:  # TCP
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif protocol == 17:  # UDP
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif protocol == 1:  # ICMP
            proto = "ICMP"
            src_port = None
            dst_port = None
        else:
            proto = "Other"
            src_port = None
            dst_port = None
        
        # Display packet information
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {proto}")
        if src_port and dst_port:
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")
        
        # Display payload data if available
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = packet[TCP].payload if packet.haslayer(TCP) else packet[UDP].payload
            print(f"Payload: {str(payload)}")
        print("-" * 50)

def start_sniffing(interface):
    print(f"Starting packet sniffing on interface {interface}...")
    # Start sniffing packets on the given interface
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # Specify the network interface to sniff on (e.g., 'eth0' for Ethernet or 'wlan0' for Wi-Fi)
    interface = input("Enter the network interface to sniff on ('eth0' for ethernet, 'wlan0' for Wi-Fi):")
    start_sniffing(interface)    
    
