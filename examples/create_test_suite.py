from example_settings import *
from packettestsuite import *

'''send ICMP echo request to 8.8.8.8/8.8.4.4 using different methods
'''

pts = PacketTestSuite('icmp tests - google dns', rx_interface = DEFAULT_INTERFACE_0, tx_interface = DEFAULT_INTERFACE_0)

pts.add_test_case('ping @ 8.8.8.8 - payload binary match', intertestcasegap = 200)
pts.current_test_case.add_tx_packet(scapy.Ether()/scapy.IP(dst='8.8.8.8')/scapy.ICMP()/scapy.Raw(load='hello dude')*2)
pts.current_test_case.add_rx_packet(CmpEther()/CmpIP(src='8.8.8.8')/CmpICMP()/CmpRaw(load='hello dude')/CmpStop(), count=2)

pts.add_test_case('ping @ 8.8.8.8 - payload regex match', intertestcasegap = 200)
pts.current_test_case.add_tx_packet(scapy.Ether()/scapy.IP(dst='8.8.8.8')/scapy.ICMP()/scapy.Raw(load='xdgh bufs'))
pts.current_test_case.add_rx_packet(CmpEther()/CmpIP(src='8.8.8.8')/CmpICMP()/CmpRaw(load_r='^(xdg)')/CmpStop())

def pre_runner(test_case, cmp_packet, rx_packet):
	''' a pre runner can be used to add new packets based on the packets from a previous test case '''
	print('*** running pre runner ****')
	test_case.add_tx_packet(scapy.Ether()/scapy.IP(dst='8.8.4.4')/scapy.ICMP())
	test_case.add_rx_packet(CmpEther()/CmpIP(src='8.8.4.4')/CmpICMP()/CmpStop())

pts.add_test_case('ping @ 8.8.4.4 - using pre runner', pre_run_processing = pre_runner)

total, good, bad = pts.run(verbose=True)

print('---\ntotal: %d\ngood: %d\nbad: %d' %(total, good, bad))