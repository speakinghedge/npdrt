from example_settings import *
import os
from testcase import *

if os.path.isfile(PCAP_FILE_NAME):

	def del_mac_addr(pckt):
		''' this preprocessor removes the mac address from the Ethernet layer.
		'''
		
		del pckt[scapy.Ether].src
		del pckt[scapy.Ether].dst
		return pckt

	ts = TestCase(name='read pcap file 5 - to rx queue', rx_interface=DEFAULT_INTERFACE_0, tx_interface=DEFAULT_INTERFACE_0)
	
	rxp, idx = ts.add_rx_pcap(PCAP_FILE_NAME, pre_processing=del_mac_addr)
	txp, idx = ts.add_tx_pcap(PCAP_FILE_NAME, pre_processing=del_mac_addr)

	print('packets in rx queue: %d' % (len(rxp)))
	print('packets in rx queue: %d' % (len(txp)))
	assert(len(rxp) == len(txp))

	for i in range(0, len(rxp)):
		assert(rxp[i].packet == txp[i].packet)

else:
	print('missing pcap file %s. abort.' % (PCAP_FILE_NAME))