# Imports
!pip install scapy
from scapy.all import *


# ---------------------------- Packets ----------------------------
# 1. Create and stack packets
# 1a. Create an IP packet and check some default values for arguments/attributes
print(80*"-")
destination = "www.google.com"
IP_packet = IP(dst=destination)

data_type = type(IP_packet)
dst_IP = IP_packet.dst
max_hops = IP_packet.ttl
source = IP_packet.src
version = IP_packet.version
flags = IP_packet.flags
checksum = IP_packet.chksum

print(f"Source = {source}\nDestination = {destination}\nIP = {dst_IP}\nIP version = {version}\n\n")
print(f"Time-To-Leave = {max_hops} (max) hops\nChecksum = {checksum}\nFlags = {flags}\n")
print(f"Data type = {data_type}")
print(80*"-")


# 1b. Create 4 different packets with 4 different IPs by using "/30" in URL that gives the net mask
packets = IP(dst="www.target.com/30")
IPs = [packet for packet in packets]
print(f"Variable IPs contains {len(IPs)} different IP packets:\n{IPs}")

# 2a. A simple stack
packet = Ether() / IP() / TCP()
print(f"My stacked packet = {packet}", '\n')
packet.show()

# 2b. Source default port = 20 (FTP), while default destination port is 80 (HTTP)
p = Ether() / IP(dst="www.secdev.org") / TCP(flags="F")
p.summary()



# 2. Access fields
pac = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="www.google.com") / TCP(flags=["F", "R"])
print("Ethernet access ------>", pac[0].dst, ' = ', pac[Ether].dst)
print("IP (network) --------->", pac[1].dst, ' = ', pac[IP].dst)
print("TCP (transport) ------>", pac[2].flags, ' = ', pac[TCP].flags)
print((pac[0] == pac[Ether]) and (pac[1] == pac[IP]) and (pac[2] == pac[TCP]))



# 3. Packet Lengths
# For every protocol
prots_names = ["Ethernet", "IP", "ICMP", "TCP", "UDP", "DNS"]
prots = [Ether, IP, ICMP, TCP, UDP, DNS]
headers_lenghts = [len(prot()) for prot in prots]
print("Headers Lengths:\n")
if len(prots) == len(prots_names):
    for i in range(len(prots)):
      print(f"{prots_names[i]} ----> {headers_lenghts[i]} Bytes")

# For stacked protocols
ETH_IP_TCP = Ether() / IP() / TCP()
ETH_IP_UDP = Ether() / IP() / UDP()
ETH_IP_ICMP = Ether() / IP() / ICMP()
print(f"Lenghts of stacked protocols:\n\nETH_IP_TCP:  {len(ETH_IP_TCP)}\nETH_IP_UDP:  {len(ETH_IP_UDP)}\nETH_IP_ICMP: {len(ETH_IP_ICMP)}")





# ---------------------------- Lists of packets ----------------------------
# 1. Examples
a = [p for p in IP(ttl=(1,5)) / ICMP()]
print(f"a contains {len(a)} packets:")
a

b = [p for p in IP() / TCP(dport=[22, 80, 443])]
print(f"b contains {len(b)} packets:")
b

c = [p for p in Ether(dst=["aa:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff"]) / IP(dst=["google.com", "amazon.com"], ttl=(1, 4)) / UDP()]
print(f"c contains {len(c)} packets:")
c



# 2. Length - Difference while using len()
eth = Ether(dst=["00:00:22:22:11:11", "ff:ca:bd:01:34:f2"])     # Contains 2 combinations  (14 Bytes)
ip = IP(dst=["google.com", "amazon.com"], ttl=(1, 4))           # Contains 8 combinations  (20 Bytes)
tcp = TCP(dport=[22, 80, 443])                                  # Contains 3 combinations  (20 Bytes)
pkt = eth / ip / tcp                                            # Contains 48 combinations (54 Bytes)

# Print each packet's length
print(len(eth))
# Print the number of different packets in pkt
print(len([p for p in eth]), '\n')
# Print each packet's length
print(len(pkt))
# Print the number of different packets in pkt
print(len([p for p in pkt]))





# ---------------------------- PacketList Data Type ----------------------------
# 1. Like before
tcp = TCP(dport=[20, 53])
ip = IP(dst=["1.1.1.1", "2.2.2.2", "3.3.3.3"])
pkt = ip / tcp
list_of_packets = [p for p in pkt]
list_of_packets
list_of_packets[0]


# Typecast
packets_list = PacketList(list_of_packets)
# Not the same as before
packets_list
# Not the same as before
packets_list[0]
