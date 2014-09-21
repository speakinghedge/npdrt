from example_settings import *
from testcase import *
import random

'''
since the kernel keeps track of tcp sessions he would kill our connection by sending RST to the target
cause he don't know anything about our SYN-packet... use the iptables rule below to filter RST packets
send by the kernel 

sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <your source interfaces IP>  -j DROP

'''

src_port = random.randrange(1025,65535)

tc_syn = TestCase('TCP connection syn', tx_interface=DEFAULT_INTERFACE_0, rx_interface=DEFAULT_INTERFACE_0)

tc_syn.add_tx_packet(scapy.Ether()/scapy.IP(dst=GOOGLE_IP)/scapy.TCP(flags='S', seq=23, ack=0, sport=src_port, dport=80))

tc_syn.add_rx_packet(CmpEther()/CmpIP(src=GOOGLE_IP)/CmpTCP(ack=24, flags=scapy_tcp_flags('SA'))/CmpStop())

def generate_syn_ack(testcase, cmp_packet, rx_packet):
	
	cmp_tcp = rx_packet.upper_layer_by_name('tcp')
	if cmp_tcp is None:
		raise ValueError('failed to extract TCP layer from received packet.')
	ack = cmp_tcp.get_field('seq') + 1
	seq = cmp_tcp.get_field('ack') + 1

	print('pre-run-processing: add 3-way-handshake ACK packet with ack=%d and seq=%d' %(ack, seq))
	testcase.add_tx_packet(scapy.Ether()/scapy.IP(dst=GOOGLE_IP)/scapy.TCP(flags='A', seq=seq, ack=ack, sport=src_port, dport=80), interpacketgap=1000)

	testcase.add_tx_packet(scapy.Ether()/scapy.IP(dst=GOOGLE_IP)/scapy.TCP(flags='F', seq=seq, ack=ack, sport=src_port, dport=80))

tc_syn_ack = TestCase('TCP connection syn', tx_interface=DEFAULT_INTERFACE_0, rx_interface=DEFAULT_INTERFACE_0, pre_run_processing=generate_syn_ack )

if tc_syn.run(verbose = True) == True:
	tc_syn_ack.run(verbose = True, scapy_packet = tc_syn.match_packets['rx_packet'])

	#now we can send and receive data over the established TCP connection

