# ----------------------------------- Imports -----------------------------------
!pip install scapy
from scapy.all import *
import matplotlib.pyplot as plt


# ----------------------------------- Functions -----------------------------------
# 1. sniff() - Capture packets

# 1a. Capture packets from DEFAULT INTERFACE, otherwise I must put the parameter "iface"
sniff(count=8)
# 1b. Capture packets from DEFAULT INTERFACE, otherwise I must put the parameter "iface"
sniff(count=8, prn=lambda p: p.summary())
# 1c. Combine with matplotlib
captured = sniff(count=20)
print(f"captured = {captured}\nData type = {type(captured)}\nLength = {len(captured)}\n\n")
captured.plot(lambda x:len(x))
# 1d. Filtering captured packets requires some extra libraries
!apt-get update --quiet
!apt-get install tcpdump -y --quiet
print("Updated and installed successfully!")
packets = sniff(filter="ip and tcp", count=10)
for packet in packets:
    if packet.haslayer(TCP):
        print(packet.summary())



# 2. traceroute()

# 2a. Like calling "sr" function multiple times
ans, unans = traceroute("www.secdev.org", dport=443, minttl=1, maxttl=15)
print(f"\n\nAnswered: {len(ans)} packets of data type {type(ans)}")
print(f"Unanswered: {len(unans)} packets of data type {type(unans)}")
# 2b. 3D world trace
# !pip install geoip2
# import geoip2
# 3D image
ans, unans = traceroute('www.secdev.org', maxttl=15)
ans.world_trace()
ans.trace3D()



# 3. sr() at Layer 3 for PORT SCANNING

# Create 2 packets
ip = IP(dst=["scanme.nmap.org", "amazon.com"])
tcp = TCP(dport=[22, 80, 443, 31337])
pkt1 = ip / tcp                                                       # 4 ports (22, 80, 443, 31337)
pkt2 = ip / UDP() / DNS()                                             # 1 port  (53 for DNS)
# Send packets
sent1, rcv1 = sr(pkt1, timeout=3, verbose=False)
sent2, rcv2 = sr(pkt2, timeout=3, verbose=False)
print(f"sent1: length = {len(sent1)}, data type = {type(sent1)}")
print(f"sent2: length = {len(sent2)}, data type = {type(sent2)}\n\n")
sent1.extend(sent2)
# Make table for comparison
sent1.make_table(lambda x, y: (x[IP].dst, x.sprintf('%IP.proto%/{TCP:%r,TCP.dport%}{UDP:%r,UDP.dport%}'), y.sprintf('{TCP:%TCP.flags%}{ICMP:%ICMP.type%}')))



# 4. arp() at Layer 2
# ARP Protocol is for matching IP addresses to MAC addresses at Data-Link Layer (2)
arping("192.168.1.100")
# Scapy will broadcast an ARP request to all devices on the network, asking for the MAC address associated with the IP address 192.168.46.1 (254 possible hosts)
arping("192.168.46.1/24")
