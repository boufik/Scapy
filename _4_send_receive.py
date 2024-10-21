# ----------------------------------------- Imports -----------------------------------------
!pip install scapy
from scapy.all import *


# ----------------------------------------- Write and read -----------------------------------------
# The next line will be explained later - It exists here only to be read
packet = IP(dst=["8.8.8.8", "8.8.4.4"]) / ICMP()
ans, unans = srloop(packet, inter=0.1, timeout=0.5, count=20, verbose=False)
wrpcap("scapy.pcap", ans)
read = rdpcap("scapy.pcap")

print(f"Write {len(ans)} answered packets!\nData type of these packets = {type(ans)}\n\n")
print(f"Read {len(read)} packets!\nData type of these packets = {type(read)}\n\n")
# Build the same object with .command()
read[0].summary()
read[0].command()




# ----------------------------------------- Send - Receive -----------------------------------------
# 1. send() for Layer 3 and sendp() for Layer 2
pkt_layer3 = IP(dst="1.2.3.4") / ICMP()
pkt_layer2 = Ether() / IP(dst="1.2.3.4", ttl=(1,4))
send(pkt_layer3)
sendp(pkt_layer2)

# Parameter "return_packets"
ret = send(pkt_layer3, return_packets=True)
print(ret)
print(type(read))
sendp(read)



# 2. sr1() for Layer 3
# Send one packet and receive the FIRST response at Network Layer (3)
pkt = IP(dst="8.8.8.8") / UDP() / DNS()
response = sr1(pkt, verbose=True)
if response:
    print("Received response:", response.summary())
else:
    print("No response received")

print()
response[DNS].an



# 3. srp() for Layer 2
# Send MULTIPLE packets and receive RESPONSES at Data Link Layer (2)
pkt = Ether() / IP(dst="8.8.8.8", ttl=(61, 80)) / UDP() / DNS()
results, unanswered = srp(pkt, timeout=15)
results, unanswered



# 4. srloop() for Layer 3
packet = IP(dst=["8.8.8.8", "8.8.4.4"]) / ICMP()
ans, unans = srloop(packet, inter=0.1, timeout=0.5, count=20, verbose=False)
print(type(ans), "\n", type(unans), '\n\n')
ans.multiplot(lambda x, y: (y[IP].src, (y.time, y[IP].id)), plot_xy=True)
