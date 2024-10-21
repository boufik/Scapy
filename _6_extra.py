# ------------------------------------------ Imports -------------------------------------------
!pip install scapy
from scapy.all import *
import socket


# ------------------------------------------ Design a new protocol -------------------------------------------
# 1. Create a class for my new protocol
class DNSoverTCP(Packet):
    # Attributes
    name = "DNS over TCP"
    fields_desc = [FieldLenField("len", None, fmt="!H", length_of="dns"), PacketLenField("dns", 0, DNS, length_from=lambda p: p.len)]
    # Methods - Decode the payload with DNSoverTCP
    def guess_payload_class(self, payload):
        return DNSoverTCP

# Build and parse a packet of my new protocol
pkt = DNSoverTCP(raw(DNSoverTCP(dns=DNS())))
hexdump(pkt)
print("\n")
pkt



# 2. Connect to a TCP socket
# Create a default TCP socket
sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connect to a TCP socket with: IP=8.8.8.8 (public DNS server by Google) and port=53/TCP (DNSoverTCP usage)
sck.connect(("8.8.8.8", 53))
# Create a StreamSocket
ssck = StreamSocket(sck)
# Define the default base class
ssck.basecls = DNSoverTCP
# Send the DNS query
ssck.sr1(DNSoverTCP(dns=DNS(qd=DNSQR(qname="www.amazon.com"))))



# ------------------------------------------ Certificates -------------------------------------------
load_layer("tls")
cert_github = Cert(pem2der(open("/content/github_certificate.crt").read()))  # assuming you d/l the certificate
cert_github

print(cert_github.isSelfSigned())                                         # Check if it is self signed
print(cert_github.subject)                                                # Display the subject
print(cert_github.remainingDays())                                        # Compute the number of days until expiration

# Verify issuers signatures
cert_digicert = Cert(pem2der(open("files/digicert_sha2.pem").read()))     # Assuming you d/l the certificate
print(cert_github.isIssuerCert(cert_digicert))                            # Check the signature
