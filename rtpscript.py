from scapy.config import conf
conf.ipv6_enabled = False

from scapy.all import *


def play(pkt):
    if pkt and pkt.haslayer(UDP) and pkt.haslayer(Raw):
        pkt["UDP"].payload = RTP(pkt["Raw"].load)
        #pkt["UDP"].sport = 40000
        pkt["UDP"].dport = 51796
        pkt[IP].src = "192.168.1.9"
        sendp(pkt)

sniff(filter="host 192.168.1.15", prn=play)#x.summary())

