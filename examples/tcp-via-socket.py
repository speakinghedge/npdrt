from example_settings import *
from testcase import *

tc = TestCase('using TCP via stream socket', use_tcp = True, timeout = 1500)

tc.add_tx_packet(scapy.Ether()/scapy.IP(dst=GOOGLE_IP)/scapy.TCP(dport=80)/scapy.Raw("GET / HTTP/1.0\r\n\r\n"))

tc.add_rx_packet(CmpEther()/CmpIP()/CmpTCP()/CmpRaw(load_r='google'), interface=DEFAULT_INTERFACE_0)

tc.run(verbose = True)