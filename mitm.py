from scapy.all import *

from scapy.config import conf
conf.ipv6_enabled = False

cameraip = "192.168.1.15"

deviceip = "192.168.1.9"

filterstr = "host "+cameraip
while True:
    packet = sniff(count=1, filter=filterstr)
    packet.summary()
    sendp(packet)