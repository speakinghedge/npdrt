from example_settings import *
from testcase import *

# use default interfaces defined on test case level and regex to match answer packet
ts = TestCase(name='ping 8.8.4.4', timeout = 2000, rx_interface = DEFAULT_INTERFACE_0, tx_interface = DEFAULT_INTERFACE_0)
# send an icmp echo request to 8.8.4.4
ts.add_tx_packet(scapy.Ether()/scapy.IP(dst='8.8.4.4', ttl=75)/scapy.ICMP())

# expect one icmp echo reply with ip src *.*.4.4 (use regex to match packets)
ts.add_rx_packet(CmpEther()/CmpIP(src_r=r'(.)4(.)4$')/CmpICMP()/CmpStop(), timeout=200)

ts.run(verbose=True)