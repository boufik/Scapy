# ----------------------------------- Imports -----------------------------------
!pip install scapy
from scapy.all import *



# ----------------------------------- Prints -----------------------------------
eth = Ether(dst="ff:ff:ff:ff:ff:ff")
ip = IP(dst="www.google.com")
tcp = TCP(flags=["F", "R"])
http = "GET / HTTP/1.0\r\n\r\n"
pkt = eth / ip / tcp / http

# 1. Basic prints
pkt
print(pkt)
pkt.summary()
repr(str(pkt))
print(repr(str(pkt)))


# 2. Raw prints
raw(pkt)
print(raw(pkt))
repr(raw(pkt))
print(repr(raw(pkt)))


# 3. Hexademical Form Prints
hexdump(pkt)


# 4. Layer-by-layer Prints
pkt.show()
pkt.show2()


# 5. Image-like Prints
# pkt.canvas_dump()
a = Ether() / IP(dst="www.slashdot.org") / TCP() / "GET /index.html HTTP/1.0 \n\n"
b = raw(a)
c = Ether(b)
c
