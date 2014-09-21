import collections
from multiprocessing import Process, Queue, Value, Lock
from cmppacketlayer import *
import random
import socket
import time

# debug options
DO_DEBUG = False
SHOW_RX_PACKETS = False

class PacketEntry(UniqueId):
	'''base class for RxPacket and TxPacket.
	'''

	def __init__(self, packet, interface, name=None):
		super(PacketEntry, self).__init__()
		self._packet = packet
		self._interface = interface
		self._name = name if name is not None else '<none>'

	@property
	def packet(self):
		return self._packet

	@property
	def interface(self):
		return self._interface

	@property
	def name(self):
		return self._name

class TxPacket(PacketEntry):

	def __init__(self, packet, interface, interpacketgap):
		'''create a TxPacket.

		arguments:
		packet -- instance of CmpLayer describing an expected packet
		interface -- the packet must be send over, overridden by src-MAC of the packet (if given)
		interpacketgap -- time to wait before transmitting the next packet  (in milliseconds)
		'''
		super(TxPacket, self).__init__(packet, interface)
		self._interpacketgap = interpacketgap

	@property
	def interpacketgap(self):
		return self._interpacketgap

class RxPacket(PacketEntry):

	def __init__(self, packet, interface, timeout, count = 1):
		'''create a RxPacket.

		arguments:
		packet -- instance of CmpLayer describing an expected packet
		interface -- the packet can be received on, overridden by dst-MAC of the packet (if given)
		timeout -- time to wait for a packet after the last packet was send (in milliseconds)
		count -- how often must the packet match to be accepted (default: 1)
		'''
		if not isinstance(packet, CmpLayer):
			raise TypeError('given packet is not an instance of class CmpLayer.')
		super(RxPacket, self).__init__(packet, interface)
		self._timeout = timeout

		self._count = count
		self._current_count = count
	
	@property
	def count(self):
		return self._count

	@property
	def timeout(self):
		return self._timeout

	@property
	def current_count(self):
		return self._current_count

	def reset_current_count(self):
		self._current_count = self._count
		return self._current_count

	def accept(self):
		'''check if the packet matched often enough to be finally accepted.

		returns:
		True if number of expected packets reached
		False else
		'''
		if self._current_count == 0:
			return True 
		else:
			self._current_count = self._current_count - 1
			return True if self._current_count == 0 else False


class TestCase(UniqueId):

	_if_name_list = {if_name.lower(): {'ip':scapy.get_if_addr(if_name), 'mac':scapy.get_if_hwaddr(if_name).lower()} for if_name in scapy.get_if_list()}
	_if_mac_list = {scapy.get_if_hwaddr(if_name).lower(): {'ip':scapy.get_if_addr(if_name), 'name': if_name.lower()} for if_name in scapy.get_if_list()}

	# hmm, maybe I should add a builder for test case...
	def __init__(self, name = None, intertestcasegap = 0, interpacketgap = 0, timeout = 1000, rx_interface = None, tx_interface = None, pre_run_processing = None, use_tcp = False, tcp_connect_timeout = 2000):
		'''create a new test case.

		arguments:
		name -- name of the test case (default: anon_<running_number>)
		intertestcasegap -- time in milliseconds between two test cases (default: 0)
		interpacketgap -- default value for the time between two transmitted packets in milliseconds (default: 0)
		timeout -- default value for the maximum time to be waited for a received packet after the last packet was send in milliseconds (default: 1000)
		rx_interface -- default value used if a rx-packet offers no other interface selector
		tx_interface -- default value used if a tx-packet offers no other interface selector
		pre_run_processing -- callable foo(cmp_packet, scapy_packet), first function executed by run() (default: None)
		use_tcp -- instead of sending the tx packets via AF_PACKET, use a TCP-socket (default: False)
		tcp_connect_timeout -- if use_tcp is set to True, this attribute sets the timeout for the socket connection in milliseconds (default: 2000)

		pre_run_processing can be used to generate rx/tx packets based on given packets.

		if use_tcp is set to True, the target IP and the source/target port is extracted from the first IPv4/6 layer found in the first tx packet that is 
		added to the list of tx packets. if no source port is given, the system will choose one (>1024). if given, the source IP is also extracted from 
		the first tx packet. if there is no address given, the address defined by a configured tx-interface is taken. if no tx-interface is given, 
		the packet is send using the interface determined by consulting the routing tables of the system - but this may lead to unintended packet flows. 

		all layers up to the first IPv4/6 layer are ignored when sending the packet.

		>>> tc0 = TestCase()
		>>> tc1 = TestCase()
		>>> 'anon_' in tc0.name and 'anon_' in  tc1.name
		True
		
		>>> n0 = int(tc0.name.split('_')[1])
		>>> n1 = int(tc1.name.split('_')[1])
		>>> n0 < n1 , n0 == tc0.id , n1 == tc1.id
		(True, True, True)
		
		>>> TestCase(name='foo').name
		'foo'
		'''
		
		super(TestCase, self).__init__()
		self._name = name if name is not None else 'anon_' + str(self.id)
		self._intertestcasegap = intertestcasegap
		self._interpacketgap = interpacketgap
		self._rx_interface_ctx = TestCase.get_interface(rx_interface) if rx_interface is not None else None
		self._tx_interface_ctx = TestCase.get_interface(tx_interface) if tx_interface is not None else None
		self._timeout = timeout
		self._tx_packets = []
		self._rx_packets = []
		self._pre_run_processing = pre_run_processing
		self._match_packets = None
		self._use_tcp = use_tcp
		self._sock_conf = {'socket':None, 'sport':None, 'dport':None, 'src':None, 'dst':None, 'timeout': tcp_connect_timeout}

	@property
	def name(self):
		return self._name

	@property
	def intertestcasegap(self):
		return self._intertestcasegap

	@property
	def interpacketgap(self):
		return self._interpacketgap

	@property
	def timeout(self):
		return self._timeout

	@property
	def pre_run_processing(self):
		return self._pre_run_processing

	@property
	def match_packets(self):
		'''dict containing cmp_packet and rx_packet of the last successful match.

		return:
		['rx_packet': obj, 'cmp_packet': obj] -- last matched rx_ - and cmp_packet
		'''
		return self._match_packets

	@property
	def use_tcp(self):
		'''use socket to send packets instead of AF_PACKET interface'''
		return self._use_tcp

	@property
	def sock_conf(self):
		'''config used to setup TCP socket connection'''
		return self._sock_conf

	def rx_packets(self):
		'''return list of rx packets'''
		return self._rx_packets

	def tx_packets(self):
		'''return list of tx packets'''
		return self._tx_packets

	def set_socket_config(self, packet):
		'''set the config used to setup a TCP socket connection based on a scapy packet.

		arguments:
		packet -- scapy layer packet containing at least one IPv4/6 and one TCP layer to extract src/dst port and IP address

		the IP layer must offer: dst
		the IP layer may offer: src (default: chosen by system)
		the TCP layer must offer: dport
		the TCP layer may offer: sport (default: chosen by system)

		return:
		socket config

		>>> p = scapy.Ether()/scapy.IP(src='1.2.3.4', dst='4.3.2.1')/scapy.TCP(sport=1234, dport=4321)
		>>> tc = TestCase()
		>>> tc.set_socket_config(p)
		{'src': '1.2.3.4', 'socket': None, 'dst': '4.3.2.1', 'timeout': 2000, 'dport': 4321, 'af_family': 2, 'sport': 1234}

		>>> p = scapy.Ether()/scapy.IP(src='1.2.3.4', dst='4.3.2.1')/scapy.TCP(dport=4321)
		>>> socket_conf = tc.set_socket_config(p); (socket_conf['dport'], socket_conf['src'], socket_conf['dst'])
		(4321, '1.2.3.4', '4.3.2.1')
		'''

		if not isinstance(packet, scapy.Packet):
			raise ValueError('given packet is not an instance derived from scapy.layer')

		if 'IP' in packet:
			ip = packet['IP']
		elif 'IPv6' in packet:
			ip = packet['IPv6']
		else:
			raise ValueError('given packet lacks IPv4/6 layer.')
		
		if 'src' in ip.fields:
			self._sock_conf['src'] = ip.fields['src']
		else: 
			self._sock_conf['src'] = '0.0.0.0'
		try:
			self._sock_conf['dst'] = ip.fields['dst']
		except:
			raise ValueError('given packet IP layer lacks dst attribute.')
		
		try:
			tcp = packet['TCP']
		except:
			raise ValueError('given packet lacks TCP layer.')
		try:
			self._sock_conf['dport'] = tcp.fields['dport']
		except:
			raise ValueError('given packet TCP layer lacks dport attribute.')
		if 'sport' in tcp.fields:
			self._sock_conf['sport'] = tcp.fields['sport']
		else:
			self._sock_conf['sport'] = random.randrange(1025, 65534)

		self._sock_conf['af_family'] = socket.getaddrinfo(self._sock_conf['dst'], self._sock_conf['dport'])[0][0]

		return self._sock_conf

	@staticmethod
	def get_interface(identifier="00:00:00:00:00:00"):
		'''return the interface and its mac address for the given identifier. 
		if identifier is a mac address (format xx:xx:xx:xx:xx:xx)
		the function tries to find a matching interface.
		if identifier is an interface name, the function tries
		to find a matching interface in the system.

		arguments:
		identifier -- name or MAC address of a NIC present in the system (default: 00:00:00:00:00:00 aka loopback)

		return:
		{'name': string, mac': string, 'ip': string} -- name, mac and first IP of the interface

		>>> dev = scapy.get_if_list()[0]; ip=scapy.get_if_addr(dev);mac=scapy.get_if_hwaddr(dev)
		>>> i = TestCase.get_interface(dev); i['name'] == dev, i['mac'] ==  mac, i['ip'] == ip
		(True, True, True)
		>>> i = TestCase.get_interface(mac); i['name'] == dev, i['mac'] ==  mac, i['ip'] == ip
		(True, True, True)
		'''
		identifier = identifier.lower()
		
		if identifier in TestCase._if_mac_list:
			return {'name':TestCase._if_mac_list[identifier]['name'], 'mac':identifier, 'ip':TestCase._if_mac_list[identifier]['ip']}

		if identifier in TestCase._if_name_list:
			return {'name':identifier, 'mac':TestCase._if_name_list[identifier]['mac'], 'ip':TestCase._if_name_list[identifier]['ip']}

		raise LookupError('interface with identifier %s not found.' % (identifier))

	@staticmethod
	def show_interfaces(identifier=None):
		print('---')
		if identifier is None:
			for dev_name in TestCase._if_name_list:
				print('- interface: %s' % (dev_name))
				print('  mac: %s' %(TestCase._if_name_list[dev_name]['mac']))
				print('  ip: %s' %(TestCase._if_name_list[dev_name]['ip']))

	def add_tx_packet(self, packet, pos = None, interface = None, interpacketgap = None):
		'''add a packets to tx-packet list. 

		arguments:
		packet -- packet or list of packets of type scapy.Packet to be send
		pos -- index of the packet in the tx-packet list (default: None - append)
		interface -- name or MAC of the network interface the packet must be send over (default: src-MAC of the packet (if given))
		interpacketgap -- time to wait before sending the next packet in milliseconds (default: None - use global settings from test case)

		return:
		(tx-packet, index) -- list of added TxPackets, list of indexes the TxPackets where added on into the tx-packet list

		>>> from packettestsuite import *
		>>> import scapy.all as scapy
		>>> tc = TestCase()
		>>> txp, idx = tc.add_tx_packet(scapy.Ether(src='lo')) ; print(idx[0])
		0
		>>> txp, idx = tc.add_tx_packet(scapy.Ether(src='lo')) ; print(idx[0])
		1
		>>> txp, idx = tc.add_tx_packet(scapy.Ether(src='lo')) ; print(idx[0])
		2
		>>> txp, idx = tc.add_tx_packet(scapy.Ether(src='lo'), pos = -1) ; print(idx[0])
		2
		>>> txp, idx = tc.add_tx_packet(scapy.Ether(src='lo'), pos = 100) ; print(idx[0])
		4
		>>> txp, idx = tc.add_tx_packet(scapy.Ether(src='lo'), pos = -100) ; print(idx[0])
		0
		>>> txp, idx = tc.add_tx_packet(scapy.Ether(src='lo')*2, pos = -100) ; print(idx)
		[0, 1]
		>>> txp, idx = tc.add_tx_packet(scapy.Ether(src='lo')*2) ; print(idx)
		[8, 9]
		>>> txp, idx = tc.add_tx_packet(scapy.Ether(src='lo')*2, pos = -1); print(idx)
		[9, 10]

		>>> tc = TestCase(name = 'using tcp socket', use_tcp = True)
		>>> txp, idx = tc.add_tx_packet(scapy.Ether()/scapy.IP(dst='1.2.3.4')/scapy.TCP(dport=1234)); (tc.sock_conf['dport'], tc.sock_conf['src'], tc.sock_conf['dst'])
		(1234, '0.0.0.0', '1.2.3.4')
		>>> tc.sock_conf['sport'] > 1024 and tc.sock_conf['sport'] < 65535
		True

		>>> tc = TestCase(name = 'using tcp socket', use_tcp = True)
		>>> txp, idx = tc.add_tx_packet(scapy.Ether()/scapy.IP(dst='1.2.3.4', src='5.6.7.8')/scapy.TCP(dport=1234, sport=5678)); tc.sock_conf
		{'src': '5.6.7.8', 'socket': None, 'dst': '1.2.3.4', 'timeout': 2000, 'dport': 1234, 'af_family': 2, 'sport': 5678}

		'''

		if packet is None:
			raise ValueError('no packet(s) given.')

		interpacketgap = interpacketgap if interpacketgap is not None else self._interpacketgap

		if not isinstance(packet, collections.Iterable):
			packet = [packet]

		arr_txp = []
		arr_idx = []

		for cur_packet in packet:
			
			if not isinstance(cur_packet, scapy.Packet):
				raise TypeError('given packet is not an instance of type scapy.Packet')

			if_ctx = None

			if not self.use_tcp:
				if interface is not None:
					if_ctx = TestCase.get_interface(interface)
				elif 'src' in cur_packet.fields:
						if_ctx = TestCase.get_interface(cur_packet.fields['src'])
				elif self._tx_interface_ctx is not None:
					if_ctx = self._tx_interface_ctx
				else:
					raise ValueError('failed to resolve tx interface: no interface attribute or src field in given packet and no default tx interface for test case `' + self._name + '` given.')
			else:
				if len(self._tx_packets) == 0:
					self.set_socket_config(cur_packet)

			arr_txp.append(TxPacket(cur_packet, if_ctx, interpacketgap))
			arr_idx.append(insert_at(self._tx_packets, pos, arr_txp[-1]))
			pos = arr_idx[-1] + 1

		return arr_txp, arr_idx

	def add_tx_pcap(self, file_name, selected_packets = None, pos = None, interface = None, interpacketgap = None, pre_processing = None, **pre_processing_kwargs):
		'''add packets to tx-packet list from given pcap file.

		arguments:
		file_name -- the name of the pcap to be used
		selected_packets -- list of indexes of packets inside the pcap to be added
		pos -- index of the packet in the tx-packet list (default: None - append)
		interface --interface -- name or MAC of the network interface the packet must be send over, (default: src-MAC of the packet (if given))
		interpacketgap -- time to wait before sending the next packet in milliseconds (default: None - use global settings from test case)
		
		pre_processing -- callable foo(scapy_packet), must return the processed packet of type scapy.Packet if the packet should be added to the tx-packet list, None if the packet is ignored
		pre_processing_kwargs -- optional arguments handed over to the pre_processing function

		return:
		(count, tx-list, idx-list) -- number of packets added, list of the tx-packets, index of each packet in the tx-packet list
		'''

		pcap = scapy.rdpcap(file_name)

		idx = 0
		pckt_lst = []
		for pckt in pcap:
			if (selected_packets is not None and idx in selected_packets) or selected_packets is None:
				if pre_processing is not None and callable(pre_processing):
					if len(pre_processing_kwargs) > 0:
						pckt = pre_processing(pckt, pre_processing_kwargs)
					else:
						pckt = pre_processing(pckt)
				if pckt is not None:
					pckt_lst.append(pckt)
			idx = idx + 1
		
		return self.add_tx_packet(pckt_lst, pos=pos, interface=interface, interpacketgap=interpacketgap)

	def add_rx_packet(self, packet, count = 1, pos = None, interface = None, timeout = None):
		'''add a packet to the rx-packet list. 

		arguments:
		packet -- packet or list of packets of type CmpLayer used to compare against received packets
		count -- number of times the packet must match a single received packet to match finally (default: 1)
		pos -- index of the packet in the rx-packet list (default: None - append)
		interface -- name or MAC of the network interface the packet must be received on (default: dst-MAC of the packet (if given))
		timeout -- time to wait for a packet after the last packet was send (in milliseconds) (default: None - use global settings from test case)

		return:
		(rx-packet, index) -- list of added RxPackets, list of indexes the RxPackets where added on into the rx-packet list

		>>> from packettestsuite import *
		>>> tc = TestCase(TestCase.get_interface)
		>>> rxp, idx = tc.add_rx_packet(CmpLayer('testlayer'), interface='lo'); print(idx[0])
		0
		>>> rxp, idx = tc.add_rx_packet(CmpLayer('Ether', dst = '00:00:00:00:00:00')); print(idx[0])
		1
		>>> rxp, idx = tc.add_rx_packet(CmpLayer('Ether', dst = 'lo'), pos = -1); print(idx[0])
		1
		>>> rxp, idx = tc.add_rx_packet(CmpLayer('Ether'), interface='lo'); rxp[0].accept()
		True
		>>> rxp, idx = tc.add_rx_packet(CmpLayer('Ether'), count = 3, interface='lo'); rxp[0].accept(), rxp[0].accept(), rxp[0].accept()
		(False, False, True)
		>>> rxp, idx = tc.add_rx_packet([CmpLayer('Ether', dst = 'lo'),CmpLayer('Ether', dst = 'lo'),CmpLayer('Ether', dst = 'lo')], pos = -10); print(idx)
		[0, 1, 2]
		>>> rxp, idx = tc.add_rx_packet([CmpLayer('Ether', dst = 'lo'),CmpLayer('Ether', dst = 'lo'),CmpLayer('Ether', dst = 'lo')], pos = None); print(idx)
		[8, 9, 10]
		>>> rxp, idx = tc.add_rx_packet([CmpLayer('Ether', dst = 'lo'),CmpLayer('Ether', dst = 'lo')], pos = -1); print(idx)
		[10, 11]
		'''

		if packet is None:
			raise ValueError('no packet given.')

		if not isinstance(packet, collections.Iterable):
			packet = [packet]

		arr_rxp = []
		arr_idx = []
		timeout = timeout if timeout is not None else self._timeout
		for cur_packet in packet:

			if not isinstance(cur_packet, CmpLayer):
				raise TypeError('given packet is not an instance of class CmpLayer.')

			# TODO: if there is no interface given - accept packet from every interface ?!?
			if interface is not None:
				if_ctx = TestCase.get_interface(interface)
			elif cur_packet.contains_field('dst') is True:
					if_ctx = TestCase.get_interface(cur_packet.get_field('dst'))
			elif self._rx_interface_ctx is not None:
				if_ctx = self._rx_interface_ctx
			else:
				raise ValueError('failed to resolve rx interface: no interface attribute or src field in given packet and no default rx interface for test case `' + self._name + '` given.')

			arr_rxp.append(RxPacket(cur_packet, if_ctx, timeout, count))

			arr_idx.append(insert_at(self._rx_packets, pos, arr_rxp[-1]))
			pos = arr_idx[-1] + 1

		return arr_rxp, arr_idx

	def add_rx_pcap(self, file_name, selected_packets = None, pos = None, interface = None, timeout = None, pre_processing = None, **pre_processing_kwargs ):
		'''add packets to rx-packet list from given pcap file.

		arguments:
		file_name -- the name of the pcap to be used
		selected_packets -- list of indexes of packets inside the pcap to be added
		pos -- index of the packet in the rx-packet list (default: None - append)
		interface --interface -- name or MAC of the network interface the packet must be send over, (default: dst-MAC of the packet (if given))
		timeout -- time to wait for a packet after the last packet was send (in milliseconds) (default: None - use global settings from test case)
		
		pre_processing -- callable foo(scapy_packet), must return the processed packet of type scapy.Packet if the packet should be added to the rx-packet list, None if the packet is ignored
		pre_processing_kwargs -- optional arguments handed over to the pre_processing function

		return:
		(count, rx-list, idx-list) -- number of packets added, list of the rx-packets, index of each packet in the tx-packet list
		'''

		pcap = scapy.rdpcap(file_name)

		idx = 0
		pckt_lst = []
		for pckt in pcap:
			if (selected_packets is not None and idx in selected_packets) or selected_packets is None:
				if pre_processing is not None and callable(pre_processing):
					if len(pre_processing_kwargs) > 0:
						pckt = pre_processing(pckt, pre_processing_kwargs)
					else:
						pckt = pre_processing(pckt)
				if pckt is not None:
					pckt_lst.append(CmpLayer.from_scapy_packet(pckt))
			idx = idx + 1
		
		return self.add_rx_packet(pckt_lst, pos=pos, interface=interface, timeout=timeout)

	def remove_rx_packet(self, index):
		'''add a packet given by index from the rx packet list

		NOTE: this operation invalidates the indexes returned by add_rx_* of the remaining packets following the removed packet in the list

		>>> tc = TestCase()
		>>> rxp_0, idx_0 = tc.add_rx_packet(CmpEther(src = '1.1.1.1.1.1'), interface='lo')
		>>> rxp_1, idx_1 = tc.add_rx_packet(CmpEther(src = '2.2.2.2.2.2'), interface='lo')
		>>> rxp_2, idx_2 = tc.add_rx_packet(CmpEther(src = '3.3.3.3.3.3'), interface='lo')
		>>> tc.remove_rx_packet(idx_1[0])
		>>> rxps = tc.rx_packets()
		>>> len(rxps) == 2
		True
		>>> rxps[0].packet.id == rxp_0[0].packet.id or rxps[0].packet.id == rxp_2[0].packet.id
		True
		>>> rxps[1].packet.id == rxp_0[0].packet.id or rxps[1].packet.id == rxp_2[0].packet.id
		True
		>>> last_id = rxps[1].packet.id
		>>> tc.remove_rx_packet(0)
		>>> len(tc.rx_packets()) == 1
		True
		>>> tc.rx_packets()[0].packet.id == last_id
		True
		>>> tc.remove_rx_packet(0)
		>>> len(tc.rx_packets()) == 0
		True
		'''

		del self._rx_packets[index]
		self._match_packets = None

	def remove_all_rx_packets(self):
		'''remove all packets from rx packet list

		>>> tc = TestCase()
		>>> rxp_0, idx_0 = tc.add_rx_packet(CmpEther(src = '1.1.1.1.1.1'), interface='lo')
		>>> rxp_1, idx_1 = tc.add_rx_packet(CmpEther(src = '2.2.2.2.2.2'), interface='lo')
		>>> rxp_2, idx_2 = tc.add_rx_packet(CmpEther(src = '3.3.3.3.3.3'), interface='lo')
		>>> tc.remove_all_rx_packets()
		>>> rxps = tc.rx_packets()
		>>> len(rxps) == 0
		True
		'''

		del self._rx_packets[:]
		self._match_packets = None

	@staticmethod
	def _rx_compare(interface, cmp_packet_list, packet, tstart, tstart_lock, tnow, ret_queue, ret_queue_lock):
		'''compare received packet with packets given in cmp_packet_list.

		arguments:
		cmp_packet_list -- list of packets of type CmpLayer used to compare against scapy.Packet
		packet -- received scapy packet to be compared with CmpLayer-packets
		tstart -- time the last packet was transmitted (time the rx timeout starts to run)
		tstart_lock -- lock to protect the shared tstart value
		tnow -- current time
		ret_queue -- in case of a match place the CmpLayer-packet and scapy.Packet into that queue
		ret_queue_lock -- lock to protect the shared ret_queue

		return:
		True on successful match
		False else
		'''

		if DO_DEBUG is True:
			print('%f: received on interface %s' % (tnow, interface))
		if SHOW_RX_PACKETS is True:
			print('packet: ' + str(vars(packet)))

		with tstart_lock:
				_tstart = tstart.value

		if _tstart != 0.0:
			tdiff = (tnow - _tstart) * 1000
		else:
			tdiff = 0

		ign_pckt_cnt = 0
		for cmp_packet in cmp_packet_list:
			'''check if packet is within timeout limit.

			note: timeout starts after the last packet of the test case was send
			'''

			if tdiff < cmp_packet.timeout:
				if cmp_packet.packet == packet:
					if cmp_packet.accept() is True:
						with ret_queue_lock:
							ret_queue.put({'cmp_packet': cmp_packet.packet, 'rx_packet': CmpLayer.from_scapy_packet(packet)})
						return True
					else:
						''' TODO: maybe we should continue the loop at this point for the remaining packets 
						so if there is another packet that matches (and is accepted) is also taken into account...
						'''
						if DO_DEBUG is True:
							print('packet match but need %d more packet(s).' % (cmp_packet.current_count))
						return False
				else:
					if DO_DEBUG is True:
						print(cmp_packet.packet.reason)
			else:
				ign_pckt_cnt += 1
				if DO_DEBUG is True:
						print('ignore packet cause it is outside of the timeout (tout: %d , tdiff: %d)' % (cmp_packet.timeout, tdiff))

		return ign_pckt_cnt == len(cmp_packet_list)

	@staticmethod
	def _rx_worker(interface, packet_list, rx_timeout_start, rx_timeout_start_lock, rx_timeout, ret_queue, ret_queue_lock):
		'''handles the packet capture for a given interface.'''

		if DO_DEBUG is True:
			print('started sniffer on interface %s with a rx packet chain of length: %d' % (interface, len(packet_list)))

		scapy.sniff(iface=interface, count=0, stop_filter= lambda x : TestCase._rx_compare(interface, packet_list, x, rx_timeout_start, rx_timeout_start_lock, scapy.time.time(), ret_queue, ret_queue_lock))

		''' we may leave after a packet matched or all rx packets timed out '''
		with ret_queue_lock:
			if DO_DEBUG is True:
				if not ret_queue.empty():
					print('rx packet matched - stop sniffer on interface %s' % (interface))
				else:
					print('all rx packets timed out - stop sniffer on interface %s' % (interface))

	@staticmethod
	def _tx_worker(testcase):
		'''handles the packet transmitting.'''

		if DO_DEBUG is True:
			print('started tx process with a tx packet chain of length: %d' % (len(testcase._tx_packets)))

		if testcase.use_tcp:

			socket.setdefaulttimeout(testcase.sock_conf['timeout']/1000.)

			if testcase.sock_conf['socket'] is not None:
				testcase.sock_conf['socket'].close()
				testcase.sock_conf['socket'] = None

			testcase.sock_conf['socket'] = socket.socket(testcase.sock_conf['af_family'])
			testcase.sock_conf['socket'].bind((testcase.sock_conf['src'], testcase.sock_conf['sport']))
			
			try:
				testcase.sock_conf['socket'].connect((testcase.sock_conf['dst'], testcase.sock_conf['dport']))
			except socket.timeout:
				raise IOError('socket timeout - failed to connect from %s:%d to %s:%d.' % (testcase.sock_conf['src'], testcase.sock_conf['sport'], testcase.sock_conf['dst'], testcase.sock_conf['dport']))
			except:
				raise IOError('socket error - failed to connect from %s:%d to %s:%d.' % (testcase.sock_conf['src'], testcase.sock_conf['sport'], testcase.sock_conf['dst'], testcase.sock_conf['dport']))

			stream = scapy.StreamSocket(testcase.sock_conf['socket'])

			for pckt in testcase._tx_packets:
				if DO_DEBUG is True:
					print('send packet via stream socket from %s:%d to %s:%d' % (testcase.sock_conf['src'], testcase.sock_conf['sport'], testcase.sock_conf['dst'], testcase.sock_conf['dport']))
				try:
					stream.send(pckt.packet[scapy.TCP].payload)
				except socket.timeout:
					testcase.sock_conf['socket'].close()
					testcase.sock_conf['socket'] = None
					raise IOError('socket timeout - failed to send from %s:%d to %s:%d.' % (testcase.sock_conf['src'], testcase.sock_conf['sport'], testcase.sock_conf['dst'], testcase.sock_conf['dport']))
				except:
					testcase.sock_conf['socket'].close()
					testcase.sock_conf['socket'] = None
					raise IOError('socket error - failed to send from %s:%d to %s:%d.' % (testcase.sock_conf['src'], testcase.sock_conf['sport'], testcase.sock_conf['dst'], testcase.sock_conf['dport']))
		else:
		
			for pckt in testcase._tx_packets:
				if DO_DEBUG is True:
					print('send packet on interface %s' % (pckt.interface['name']))
				scapy.sendp(pckt.packet, inter = pckt.interpacketgap/1000.0, iface=pckt.interface['name'], verbose = False)

	def run(self, verbose = False, cmp_packet = None, scapy_packet = None):
		'''execute the test case.

		arguments:
		verbose -- if set to True, show debug output (default: False)
		cmp_packet -- packet of type CmpLayer (default: None)
		scapy_packet -- packet of type scapy.Packet (default: None)

		cmp_packet and scapy_packet are used by pre_run function, if such a function is given.

		return:
		True if the test case succeeded (access to the cmp_packet and the received packet via match_packets())
		False if the test case failed (no given cmp_packet matched the received packet(s))
		'''

		if self.pre_run_processing is not None and callable(self.pre_run_processing):
			self.pre_run_processing(self, cmp_packet, scapy_packet)

		if len(self._tx_packets) == 0 and len(self._rx_packets) == 0:
			# the empty test case always succeeds
			return True

		max_rx_timeout = 0
		rx_packets_by_if = {}
		rxps = []
		ret_queue = Queue()
		ret_queue_lock = Lock()
		rx_timeout_start = Value('d', 0.0)
		rx_timeout_start_lock = Lock()
		self._match_packets = None

		if len(self._rx_packets) > 0:
			for rxp in self._rx_packets:
				if rxp.timeout > max_rx_timeout:
					max_rx_timeout = rxp.timeout
				if rxp.interface['name'] not in rx_packets_by_if:
					rx_packets_by_if[rxp.interface['name']] = []
				rx_packets_by_if[rxp.interface['name']].append(rxp)
			
			for interface in rx_packets_by_if:
				rxps.append(Process(target=self._rx_worker, args=(interface, rx_packets_by_if[interface], rx_timeout_start, rx_timeout_start_lock, max_rx_timeout, ret_queue, ret_queue_lock)))

		if verbose is True:
			print('---')
			print('test case: %s' % (self.name))
			print('send-via-tcp-socket: %s' % (str(self._use_tcp)))
			print('tx-packets: %d' % (len(self._tx_packets)))
			print('rx-packets: %d' % (len(self._rx_packets)))
			print('max-rx-timeout: %d' % (max_rx_timeout))

		txp = None
		if len(self._tx_packets) > 0:
			txp = Process(target=self._tx_worker, args=(self,))		

		for rxp in rxps:
			rxp.start()

		''' wait a small amount of time to give the sniffers a chance to settle down 
		TODO: how to work around ?!? '''
		time.sleep(0.1)

		if txp is not None:
			txp.start()

			# wait until all packets are send or we got a packet that matches our criteria
			while True:
				txp.join(1)
				if txp.is_alive() is False or ret_queue.empty() is False:
					break

		# wait if one of the rx processes catches a packet or we run in timeout
		if ret_queue.empty() is True:

			with rx_timeout_start_lock:
				rx_timeout_start.value = scapy.time.time()
				tstart = rx_timeout_start.value

			while True:
				for rxp in rxps:
					rxp.join(1)

				if (ret_queue.empty() is False) or ((scapy.time.time() - tstart)*1000 >= max_rx_timeout):
					break

		# stop all processes
		if txp is not None and txp.is_alive():
			txp.terminate()

		with ret_queue_lock:
			for rxp in rxps:
				if rxp.is_alive():
					rxp.terminate()

		if (self._use_tcp == True) and (self.sock_conf['socket'] is not None):
			self.sock_conf['socket'].close()
			self.sock_conf['socket'] = None
			if DO_DEBUG:
				print('TCP socket closed.')

		if ret_queue.empty() and len(self._rx_packets) > 0:
			if verbose is True:
				print('test-result: failed')
			return False
		else:
			if verbose is True:
				print('test-result: success')

			if len(self._rx_packets) > 0:
				self._match_packets = ret_queue.get()
				pckts = self._match_packets

				if DO_DEBUG:

					while True:
						print('---')
						print('received packet: ' +  str(pckts['rx_packet']))
						print('matched packet: ' +  str(pckts['cmp_packet']))

						if ret_queue.empty():
							break
						pckts = ret_queue.get()

			return True
			