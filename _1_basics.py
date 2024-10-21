!pip install scapy
from scapy.all import *

# List components
lsc()

# Packet arguments
print("-------- Ethernet packet fields --------")
ls(Ether, verbose=True)
print("\n\n-------- IP packet fields --------")
ls(IP, verbose=True)
print("\n\n-------- TCP packet fields --------")
ls(TCP, verbose=True)
print("\n\n-------- UDP packet fields --------")
ls(UDP, verbose=True)
