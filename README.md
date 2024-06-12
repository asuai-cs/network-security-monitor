# network-security-monitor 
import scapy.all as scapy
import pandas as pd
from datetime import datetime

# Function to capture packets
def capture_packets(packet):
 if packet.haslayer(scapy.IP):
     packet_info = {
         "timestamp": datetime.now(),
         "source_ip": packet[scapy.IP].src,
         "destination_ip": packet[scapy.IP].dst,
         "protocol": packet[scapy.IP].proto,
         "length": len(packet)
    }
    return packet_info
    
# Capture packets and store them in a DataFrame
packets = []
scapy.sniff (prn=lambda x: packets.append(capture_packets(x)), count=100)
df = pd.DataFrame(packets)

# Anomaly detection (e.g., detecting unusually large packets)
anomalies = df[df['length'] > 1500]


# Save the captured data to a CSV file
df.to_csv('network_traffic.csv', index=False)
anomalies.to_csv('anomalies.csv', index=False)
print("Captured network traffic saved to network_traffic.csv")
print("Anomalies saved to anomalies.csv")
