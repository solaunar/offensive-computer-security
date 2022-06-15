from scapy.config import conf
conf.ipv6_enabled = False

from scapy.all import *
import logging
import sys

root = logging.getLogger()
root.setLevel(logging.INFO)

# Get camera IP & mac
camera_ip = "192.168.1.14"
camera_mac = getmacbyip(camera_ip)
logging.info('Camera IP Address: {address}.'.format(address = camera_ip))
logging.info('Camera MAC Address: {address}.'.format(address = camera_mac))

# Get router ip & mac (local)
router_ip = conf.route.route("0.0.0.0")[2]
logging.info('Router IP Address: {address}.'.format(address = router_ip))
router_mac = None
while (router_mac == None):
    router_mac = getmacbyip(router_ip)
logging.info('Router MAC Address: {address}.'.format(address = router_mac))

# Get own device ip & mac
attacker_ip = conf.route.route("0.0.0.0")[1]
attacker_mac = get_if_hwaddr(conf.iface)
logging.info('Attacker IP Address: {address}.'.format(address = attacker_ip))
logging.info('Attacker MAC Address: {address}.'.format(address = attacker_mac))