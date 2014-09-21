from packettestsuite import *
import random
import time

''' 
test switch behavior for unknown/known MAC-addresses

to be able to run the test more then once (without reseting the address tables of the switch)
random MAC addresses are used

!!! adapt list of MAC addresses in NETWORK_PORTS to your own needs !!! 

my setup_

 4-port NIC        switch
 ---------+       +-------
 *0b:dc:2a|-------|
 *0b:dc:2b|-------|
 *0b:dc:2c|-------|
 *0b:dc:2d|-------|
 ---------+       +-------

'''

''' network interfaces to be used within the test '''
NETWORK_PORTS = [ '00:e0:ed:0b:dc:2a', '00:e0:ed:0b:dc:2b', '00:e0:ed:0b:dc:2c', '00:e0:ed:0b:dc:2d' ]


class RndMACGenerator:

	def __init__(self):

		self.bytes = range(0, 256)
		self.rnd = random.Random(time.time())
		#self.rnd_byte = lambda : random.Random(time.time()).choice(self.b)

	def rnd_byte(self, without = ()):
		
		tmp_bytes = self.bytes
		
		if without is not None:
			tmp_bytes = [ v for v in self.bytes if v not in without]

		return self.rnd.choice(tmp_bytes)

	def get(self, individual_address = True):
		
		return '%02x:%02x:%02x:%02x:%02x:%02x' % ((self.rnd_byte() & 254 if individual_address else self.rnd_byte() | 1), self.rnd_byte(), self.rnd_byte(), self.rnd_byte(), self.rnd_byte(), self.rnd_byte((0, 0xff)))

if __name__ == '__main__':

	rmg = RndMACGenerator()

	''' 1. check broadcasting if target MAC is unknown '''

	for idx, tx_port in enumerate(NETWORK_PORTS):

		print '**** (%d/%d) send via %s ****' % (idx + 1, len(NETWORK_PORTS), tx_port) 
		tc = TestCase(name='tx via ' + tx_port, timeout = 1000)

		tx_src_mac = rmg.get()
		tx_dst_mac = rmg.get()
		tc.add_tx_packet(scapy.Ether(src = tx_src_mac, dst = tx_dst_mac)/scapy.IP(dst='1.2.3.4')/scapy.TCP()/scapy.Raw(load='dummy'), interface = tx_port)

		rx_ports = [port for port in NETWORK_PORTS if port <> tx_port]

		for idx, rx_port in enumerate(rx_ports):
			
			print '-- (%d/%d) check broadcast on port %s' % (idx + 1, len(rx_ports), rx_port)
			tc.add_rx_packet(CmpEther(src = tx_src_mac, dst = tx_dst_mac)/CmpIP(dst='1.2.3.4')/CmpTCP()/CmpRaw(load='dummy')/CmpStop(), interface = rx_port)

			#assert(tc.run() == True)
			if  not tc.run():
				sys.stderr.write('Error: check for broadcasting failed for tx(%s) -> rx(%s). abort.\n' % (tx_port, rx_port))
				sys.exit(1)
			
			tc.remove_all_rx_packets()

	''' 2. send a packet from each used NIC so the switch can learn the MAC addresses of the NICs connected to each port '''

	src_macs = dict()
	for idx, tx_port in enumerate(NETWORK_PORTS):

		src_mac = rmg.get()
		print 'send packet to learn address %s on port connected to %s ' % (src_mac, tx_port)
		tc = TestCase('send packet to learn address ' + src_mac + 'on ' + tx_port)
		tc.add_tx_packet(scapy.Ether(src = src_mac, dst = rmg.get())/scapy.IP(dst='1.2.3.4')/scapy.TCP()/scapy.Raw(load='dummy'), interface = tx_port)
		src_macs[tx_port] = src_mac
		tc.run()

	''' 3. check that a packet with a known target is only delivered to the right port '''

	net_ports = NETWORK_PORTS
	for i in range(0, len(net_ports)):

		src_port = net_ports[0]
		target_port = net_ports[1]
		rx_ports = net_ports[2:]

		tc = TestCase('test proper delivery with source ' + src_port + ' and target ' +  target_port)

		tc.add_tx_packet(scapy.Ether(src = src_macs[src_port], dst = src_macs[target_port])/scapy.IP(dst='1.2.3.4')/scapy.TCP()/scapy.Raw(load='dummy'), interface = src_port)

		''' check target port catches the packet '''
		tc.add_rx_packet(CmpEther(src = src_macs[src_port], dst = src_macs[target_port])/CmpIP(dst='1.2.3.4')/CmpTCP()/CmpRaw(load='dummy')/CmpStop(), interface = target_port)

		if not tc.run():
			sys.stderr.write('Error: check for direct packet delivering failed for tx(%s) -> rx(%s). abort.\n' % (src_port, target_port))
			sys.exit(1)

		''' check no other port gets the packet '''
		tc.remove_all_rx_packets()
		for rx_port in rx_ports:
			tc.add_rx_packet(CmpEther(src = src_macs[src_port], dst = src_macs[target_port])/CmpIP(dst='1.2.3.4')/CmpTCP()/CmpRaw(load='dummy')/CmpStop(), interface = rx_port)

		if tc.run():
			sys.stderr.write('Error: check for direct packet delivering failed - got packet on invalid port')
			sys.exit(1)

		net_ports = rx_ports
		net_ports.insert(0, target_port)
		net_ports.append(src_port)

	print '\n**** TEST PASSED ****\n'
