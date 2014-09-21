
from example_settings import *
import os
from testcase import *

if os.path.isfile(PCAP_FILE_NAME):
	# -------------------------------------------------
	ts = TestCase(name='read pcap file 1 - read all')
	txp, idx = ts.add_tx_pcap(PCAP_FILE_NAME, interface = DEFAULT_INTERFACE_0)
	print('packets in pcap: %d' % (len(txp)))
	pcap_pckt_count = len(txp)

	# -------------------------------------------------
	ts = TestCase(name='read pcap file 2 - selected packets')
	pckt_selector = [0, 1 ,2 , 3]
	txp, idx = ts.add_tx_pcap(PCAP_FILE_NAME, interface = DEFAULT_INTERFACE_0, selected_packets = pckt_selector)
	if len(txp) != len(pckt_selector):
		print('add_tx_pcap - selector not working: expected %d packets in tx queue - but have %d.' % (len(txp), len(pckt_selector)))
	
	# -------------------------------------------------
	ts = TestCase(name='read pcap file 3 - use pre_processing')

	def fix_src_mac(pckt):
		''' this preprocessor changes the src mac address to the address of the default interface so the
		add_tx_pcap function is able to select the tx interface by the address of the packet.
		'''
		if_ctx = TestCase.get_interface(DEFAULT_INTERFACE_0)
		pckt[scapy.Ether].src = if_ctx['mac']
		return pckt

	txp, idx = ts.add_tx_pcap(PCAP_FILE_NAME, selected_packets = pckt_selector, pre_processing = fix_src_mac)
	print('packets in tx-queue: %d, expected: %d' % (len(txp), len(pckt_selector)))
	if_ctx = TestCase.get_interface(DEFAULT_INTERFACE_0)
	print('mac addr of interface %s is: %s' % (if_ctx['name'], if_ctx['mac']))
	for pckt in txp:
		print('if_ctx for tx packet: %s' % (pckt.interface))

	# -------------------------------------------------
	ts = TestCase(name='read pcap file 4 - use pre_processing with arguments', tx_interface=DEFAULT_INTERFACE_0)

	drop_cntr = 0
	def filter_by_ip(pckt, args):
		global drop_cntr 
		if pckt[scapy.IP].src == args['ip'] or pckt[scapy.IP].dst == args['ip']:
			drop_cntr = drop_cntr + 1
			return None
		else:
			return fix_src_mac(pckt)

	txp, idx = ts.add_tx_pcap(PCAP_FILE_NAME, pre_processing = filter_by_ip, ip='192.168.1.23')
	print('packets dropped: %d' % (drop_cntr))
	print('packets added: %d' % (len(txp)))
	assert(pcap_pckt_count == (drop_cntr + len(txp)))
else:
	print('missing pcap file %s. abort.' % (PCAP_FILE_NAME))