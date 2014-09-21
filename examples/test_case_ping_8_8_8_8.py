from example_settings import *
from testcase import *

ts = TestCase(name='ping 8.8.8.8', timeout = 2000)

# send 6 ICMP echo requests to 8.8.8.8, scapy takes care to add the needed/missing informations on each layer
ts.add_tx_packet(scapy.Ether()/scapy.IP(dst='8.8.8.8', ttl=75)/scapy.ICMP()*6, interface=DEFAULT_INTERFACE_0, interpacketgap = 400)

ts.add_rx_packet(CmpEther()/CmpIP(src_r=r'208$')/CmpICMP()/CmpLayer('Raw'), interface=DEFAULT_INTERFACE_0, timeout=200)

# expect 6 ICMP replies from 8.8.8.8
# ICMP response may contain additional Raw- or Padding- layer - so ignore everything after CmpICMP-layer
ts.add_rx_packet(CmpEther()/CmpIP(src='8.8.8.8')/CmpICMP()/CmpStop(), interface=DEFAULT_INTERFACE_0, timeout=4000, count=6)

ts.run(verbose=True)