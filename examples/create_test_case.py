from example_settings import *
from testcase import *

''' create a test case sending a ping to 8.8.8.8
'''

tc = TestCase(name='small example', timeout = 2000, interpacketgap = 200, rx_interface = DEFAULT_INTERFACE_0, tx_interface = DEFAULT_INTERFACE_0)

tc.add_tx_packet(scapy.Ether()/scapy.IP(dst='8.8.8.8')/scapy.ICMP()/scapy.Raw(load='hello dude')*2)
tc.add_rx_packet(CmpEther()/CmpIP(src='8.8.8.8')/CmpICMP()/CmpRaw(load='hello dude')/CmpStop(), count=2)

if tc.run() is True:
	print('test case `%s` succeeded.' % (tc.name))
else:
	print('test case `%s` failed.' % (tc.name))