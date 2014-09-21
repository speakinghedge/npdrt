from helper import *
import scapy.all as scapy
from copy import deepcopy
import re

class CmpLayer(UniqueId):
	''' defines a packet layer / a chain of packet layers used to compare against a scapy.Packet.
	'''

	def __init__(self, layer_name, field_regex_postfix = '_r', **fields):

		''' creates a packet layer.

		arguments:
		layer_name -- name of the packet layer (eg. Ether, IP, TCP,...)
		fields -- a dictionary of properties
		field_regex_postfix -- postfix that marks a key used in the fields argument as a regular expression (eg. src_r='(..:){5}ff')

		>>> cmp = CmpLayer('IP', src = '192.168.1.1', dst = '141.56.1.1')
		>>> print(str(cmp))
		CmpIP(fields:{'src': '192.168.1.1', 'dst': '141.56.1.1'})
		'''
		super(CmpLayer, self).__init__()

		if layer_name != 'NoPayload':
			self._payload = CmpLayer('NoPayload');
		else:
			self._payload = None;
		self._name = layer_name
		self._field_regex_postfix = field_regex_postfix

		self._fields = {}
		for key in fields:
			self._fields[key] = fields[key]

		# why the last match has failed
		self._reason = ''

	@staticmethod
	def from_scapy_packet(scapy_packet):
		'''create a stack of compare layers from a given scapy packet.

		arguments:
		scapy_packet -- object of type scapy.Packet to be converted into a CmpLayer object

		return:
		cmp_packet -- object of type CmpLayer

		>>> scpy = scapy.Ether(src='11:22:33:44:55:66', dst='aa:bb:cc:dd:ee:ff')/scapy.IP(src='192.168.1.1', dst='8.8.8.8')
		>>> cmp = CmpLayer.from_scapy_packet(scpy)
		>>> str(cmp)
		"CmpEther(fields:{'src': '11:22:33:44:55:66', 'dst': 'aa:bb:cc:dd:ee:ff'})/CmpIP(fields:{'src': '192.168.1.1', 'dst': '8.8.8.8'})"
		
		>>> cmp == scpy
		True
		
		>>> scpy = scapy.Ether(src='11:22:33:44:55:66', dst='aa:bb:cc:dd:ee:ff')/scapy.IP(src='192.168.1.1', dst='8.8.4.4')
		>>> cmp == scpy
		False
		'''

		if not isinstance(scapy_packet, scapy.Packet):
			raise TypeError('given packet is not an instance of class scapy.Packet')

		layer = scapy_packet
		cmp_lyr = None
		while layer.name != 'NoPayload':

			constructor = globals()['Cmp' + layer.__class__.__name__]
			if cmp_lyr is None:
				cmp_lyr = constructor(**layer.fields)
			else:
				cmp_lyr = cmp_lyr/constructor(**layer.fields)
			layer = layer.payload

		return cmp_lyr

	@property
	def name(self):
		'''name of the layer.
		'''
		return self._name

	@property
	def fields(self):
		'''fields attribute of the layer.
		'''
		return self._fields

	@property
	def payload(self):
		'''payload of the layer.
		'''
		return self._payload

	@property
	def field_regex_postfix(self):
		'''current postfix used to mark an attribute as an regex.
		'''
		return self._field_regex_postfix

	@property
	def reason(self):
		'''reason why the last match has failed.
		'''
		return self._reason

	def upper_layer_by_name(self, name):
		'''return the next layer that has the given name.

		arguments:
		name -- name of the layer to return (without leading Cmp)

		return:
		layer if layer with matching name was found
		None else

		>>> cmp = CmpEther()/CmpIP()/CmpTCP()/CmpRaw()
		>>> ip = cmp.upper_layer_by_name('IP'); isinstance(ip, CmpIP)
		True
		
		>>> raw = cmp.upper_layer_by_name('raw'); isinstance(raw, CmpRaw)
		True
		
		>>> cmp.upper_layer_by_name('foo') == None
		True
		'''

		if self.payload is None or self.payload.name == 'NoPayload':
			return None

		if self.payload.name.upper() == name.upper():
			return self.payload

		return self.payload.upper_layer_by_name(name)


	def contains_field(self, key):
		'''check if the layer contains a given field.

		arguments:
		key -- name of the field to look up

		return: 
		True if field was found
		False else
		'''

		return True if key in self._fields else False

	def get_field(self, key):
		'''return the value of a field selected by a given key.

		arguments:
		key -- name of the field to be returned

		return:
		value of the requested field

		>>> cmp = CmpLayer(layer_name='foo', color='blue', size=23)
		>>> cmp.get_field('color')
		'blue'

		>>> cmp.get_field('size')
		23
		'''

		if self.contains_field(key):
			return self._fields[key]
		else:
			raise KeyError('field with key %s not present in packet layer %s.' % (key, self._name))

	def set_field(self, key, value):
		'''set the value of a field selected by a given key.

		arguments:
		key -- name of the field to be set
		value -- to be set into the field

		return:
		new value of the requested field

		>>> cmp = CmpLayer(layer_name='foo', color='blue', size=23)
		>>> cmp.get_field('color')
		'blue'
		
		>>> cmp.set_field('color', 'red')
		'red'
		
		>>> cmp.get_field('color')
		'red'
		'''

		self._fields[key] = value

		return self._fields[key]

	def remove_field(self, key):
		'''remove a field selected by a given key.

		arguments:
		key -- name of the field to be removed

		>>> cmp = CmpLayer(layer_name='foo', color='blue', size=23)
		>>> cmp.contains_field('color')
		True
		>>> cmp.remove_field('color')
		>>> cmp.contains_field('color')
		False
		'''
		if self.contains_field(key):
			del self._fields[key]
		else:
			raise KeyError('field with key %s not present in packet layer %s.' % (key, self._name))

	def __str__(self):
		'''return string representation of the CmpLayer.
		'''

		if not isinstance(self, CmpLayer):
			raise TypeError('given object is not an instance of class CmpLayer')

		if self._name != 'NoPayload':
			return 'Cmp' + self._name + '(fields:' + str(self._fields) + ')' + (('/' + str(self._payload)) if (self._payload is not None) and (self._payload._name != 'NoPayload') else '')
		else:
			return ''

	def _naked_key(self, key):
		'''return the given field key name without field_regex_postfix.

		arguments:
		key -- name of the key to be stripped

		return:
		key name without field_regex_postfix

		>>> cmp = CmpLayer('foo')
		>>> cmp._naked_key('bar_r')
		'bar'

		>>> cmp = CmpLayer('foo', field_regex_postfix='_bar')
		>>> cmp._naked_key('bar_bar')
		'bar'

		>>> cmp = CmpLayer('foo', field_regex_postfix='_foo')
		>>> cmp._naked_key('bar_foo_bar')
		'bar_foo_bar'
		'''
		return key if not key.endswith(self._field_regex_postfix) else (key[0: -len(self._field_regex_postfix)])

	''' __truediv__ and __floordiv__ in python 3.x - see https://docs.python.org/3.3/reference/datamodel.html#object.__truediv__ '''
	def __div__(self, value):
		''' build a chain of named packet layers using overloaded div operator.
		
		the operands are not changed and the function returns a new object.

		arguments:
		value -- object of type CmpLayer to be added as payload to the current object

		return:
		copy of self having value appended as payload

		>>> cmp_1 = CmpLayer('a')
		>>> cmp_2 = CmpLayer('b')/CmpLayer('c')/CmpLayer('d')/CmpLayer('e')
		>>> cmp_3 = cmp_1/cmp_2

		>>> print(str(cmp_1))
		Cmpa(fields:{})

		>>> print(str(cmp_2))
		Cmpb(fields:{})/Cmpc(fields:{})/Cmpd(fields:{})/Cmpe(fields:{})

		>>> print(str(cmp_3))
		Cmpa(fields:{})/Cmpb(fields:{})/Cmpc(fields:{})/Cmpd(fields:{})/Cmpe(fields:{})
		'''

		if isinstance(self, CmpLayer) and isinstance(value, CmpLayer):
			a = deepcopy(self)
			obj = a
			while obj._payload.name is not 'NoPayload':
				obj = obj._payload

			obj._payload = deepcopy(value)
			return a
		else:
			raise TypeError('given operand is not of type class CmpLayer')

	def cmp_fields(self, scapy_layer):
		'''compare the fields of an object of type CmpLayer and scapy.Packet.

		arguments:
		scapy_layer -- contains a layer of a packet that is an instance of scapy.Packet

		return:
		True -- each field present in self is equal/matches to/with the fields present in the scapy_layer
		False -- fields that are present in self are not present or equal in the scapy_layer
		'''

		for cmp_key in self.fields:

			if not cmp_key.endswith(self.field_regex_postfix):
				# cmp
				if cmp_key in scapy_layer.fields:
					if self.get_field(cmp_key) != scapy_layer.fields[cmp_key]:
						self._reason = 'layer ' + self.name + ': different values for key ' + cmp_key + ': compare:' + str(self.get_field(cmp_key)) + ' received:' + str(scapy_layer.fields[cmp_key])
						return False
				else:
					self._reason = 'layer ' + self.name + ': key ' + cmp_key + ' not in received packet'
					return False
			else:
				# regex search
				scapy_key = self._naked_key(cmp_key)
				if scapy_key in scapy_layer.fields:
					if re.search(self.get_field(cmp_key), scapy_layer.fields[scapy_key]) is None:
						self._reason = 'layer ' + self.name + ': for key ' + scapy_key + ' no match with regex:' + str(self.get_field(cmp_key)) + ' on received data:' + str(scapy_layer.fields[scapy_key])
						return False
				else:
					self._reason = 'layer ' + self.name + ': key ' + scapy_key + ' not in received packet'
					return False

		return True

	def __eq__(self, scapy_layer):
		'''compares the layer stack represented by self (CmpLayer*) with an object of type scapy.Packet.

		arguments:
		scapy_layer -- object of type scapy.Packet

		return:
		True if the scapy_packet matches this instance
		False else

		>>> cmp = CmpEther(src='aa:bb:cc:dd:ee:ff')
		>>> scpy = scapy.Ether(src='aa:bb:cc:dd:ee:ff')
		>>> cmp == scpy
		True

		>>> cmp = CmpEther(src='aa:bb:cc:dd:ee:ff', dst='11:22:33:44:55:66')
		>>> cmp == scpy
		False

		>>> scpy = scapy.Ether(src='aa:bb:cc:dd:ee:ff',  dst='11:22:33:44:55:66')
		>>> cmp == scpy
		True

		>>> cmp = CmpEther(src_r='(..:){5}ff',  dst='11:22:33:44:55:66')
		>>> cmp == scpy
		True

		>>> cmp = CmpLayer('Ethernet', src_r='(..:){5}ff',  dst='00:00:00:00:00:00')
		>>> cmp == scpy
		False

		>>> cmp = CmpEther(src_r='(..:){5}ff',  dst='11:22:33:44:55:66')/CmpLayer('IP')
		>>> cmp == scpy
		False

		>>> scpy = scapy.Ether(src='aa:bb:cc:dd:ee:ff',  dst='11:22:33:44:55:66')/scapy.IP()
		>>> cmp == scpy
		True

		>>> scpy = scapy.Ether(src='aa:bb:cc:dd:ee:ff',  dst='11:22:33:44:55:66')/scapy.IP(src='192.168.1.1', dst='141.56.1.1')
		>>> cmp == scpy
		True

		>>> cmp = CmpLayer('Ethernet', src_r='(..:){5}ff',  dst='11:22:33:44:55:66')/CmpLayer('IP', src='10.0.0.1', dst='141.56.1.1')
		>>> cmp == scpy
		False

		>>> cmp = CmpEther(src_r='(..:){5}ff',  dst='11:22:33:44:55:66')/CmpLayer('IP', src='192.168.1.1', dst='141.56.1.1')
		>>> cmp == scpy
		True

		>>> cmp = CmpEther(src_r='(..:){5}ff',  dst='11:22:33:44:55:66')/CmpLayer('IP', src='192.168.1.1', dst_r='141.56(.1){2}')
		>>> cmp == scpy
		True

		>>> cmp = CmpEther(src_r='(..:){5}ff',  dst='11:22:33:44:55:66')/CmpStop()
		>>> cmp == scpy
		True

		>>> cmp = CmpStop()
		>>> cmp == scpy
		True

		>>> cmp = CmpLayer('raw', load='abcd')
		>>> scpy = scapy.Raw(load='abcd')
		>>> cmp == scpy
		True

		>>> cmp = CmpLayer('raw', load='abcdX')
		>>> cmp == scpy
		False

		>>> cmp = CmpEther()/CmpIP()/CmpRaw(load='abcd')
		>>> scpy = scapy.Ether()/scapy.IP()/scapy.Raw(load='abcd')
		>>> cmp == scpy
		True

		>>> cmp = CmpEther()/CmpIP()/CmpRaw(load='\x61\x62\x63\x64')
		>>> scpy = scapy.Ether()/scapy.IP()/scapy.Raw(load='abcd')
		>>> cmp == scpy
		True

		>>> cmp = CmpLayer('Ethernet')/CmpLayer('IP')/CmpLayer('raw', load='\x61\x62\x63')
		>>> cmp == scpy
		False
		
		>>> cmp == None
		False
		'''

		self._reason = ''

		if scapy_layer is None:
			self._reason = 'received packet is None'
			return False

		if not isinstance(scapy_layer, scapy.Packet):
			raise TypeError('given packet is not an instance of class scapy.Packet.')

		if self.name == 'NoPayload' and scapy_layer.name == 'NoPayload':
			# no layer left - match
			return True

		if self.name != 'NoPayload' and scapy_layer.name == 'NoPayload':
			self._reason = 'received packet contains less layers'
			return False

		if self.name == 'NoPayload' and scapy_layer.name != 'NoPayload':
			self._reason = 'compare packet contains less layers'
			return False

		if self.name.lower() != scapy_layer.__class__.__name__.lower():
			self._reason = 'layer name mismatch - compare layer name:' + self.name + ' received packet layer name:' + scapy_layer.name
			return False

		if self._fields and self.cmp_fields(scapy_layer) is False:
			return False

		if (self.payload == scapy_layer.payload) is False:
			self._reason = self.payload._reason
			return False

		return True

''' generate comparable layers based on CmpLayer using scapy layer names '''
def _cmp_init(self, **args):
		org_name = self.__class__.__name__[3:]
		super(type(self), self).__init__(org_name, **args)

for layer in  scapy.conf.layers:

	# build a string that holds a type cmd that creates the new class based on the current scapy layer name
	class_factory = 'Cmp' + layer.__name__ + ' = type("Cmp' + layer.__name__ + '", (CmpLayer,), {"__init__" : _cmp_init})'
	exec(class_factory)

class CmpStop(CmpLayer):	
	'''stop comparing the layers - ignore remaining data.
		
	>>> scpy = scapy.Ether(src='aa:bb:cc:dd:ee:ff', dst='11:22:33:44:55:66')/scapy.IP(src='1.2.3.4')
	>>> cmp = CmpEther(src='aa:bb:cc:dd:ee:ff', dst='11:22:33:44:55:66')/CmpIP(src='1.2.3.4')
	>>> cmp == scpy
	True
	>>> cmp = CmpEther(src='aa:bb:cc:dd:ee:ff', dst='ba:d0:be:ef:42:23')/CmpIP(src='1.2.3.4')
	>>> cmp == scpy
	False
	>>> scpy = scapy.Ether(src='aa:bb:cc:dd:ee:ff', dst='11:22:33:44:55:66')/scapy.IP(src='1.2.3.4')/scapy.TCP()
	>>> cmp = CmpEther(src='aa:bb:cc:dd:ee:ff', dst='11:22:33:44:55:66')/CmpStop()
	>>> cmp == scpy
	True
	'''

	def __init__(self):
		super(CmpStop, self).__init__('#')

	def __eq__(self, scapy_layer):
			# ignore all remaining layers
			return True

class CmpAny(CmpLayer):
	'''this is a wild card layer that matches any scapy layer.
	'''

	def __init__(self, field_regex_postfix='_r', **fields):

		super(CmpAny, self).__init__('*', field_regex_postfix = field_regex_postfix, **fields)

	def __eq__(self, scapy_layer):
		'''
		
		>>> scpy = scapy.Ether()/scapy.IP()/scapy.TCP()/scapy.Raw()
		>>> cmp = CmpEther()/CmpIP()/CmpAny()/CmpRaw()
		>>> cmp == scpy
		True
		'''

		self._reason = ''
		if scapy_layer is None:
			self._reason = 'received packet is None'
			return False

		if not isinstance(scapy_layer, scapy.Packet):
			raise TypeError('given packet is not an instance of class scapy.Packet.')

		if scapy_layer.name == 'NoPayload':
			self._reason = 'received packet contains less layers'
			return False

		if self._fields and self.cmp_fields(scapy_layer) is False:
			return False

		if (self.payload == scapy_layer.payload) is False:
			self._reason = self.payload._reason
			return False

		return True

	def __mul__(self, n):
		'''
		>>> scpy = scapy.Ether()/scapy.IP()/scapy.TCP()/scapy.Raw()
		>>> cmp = CmpEther()/(CmpAny()*2)/CmpRaw()
		>>> cmp == scpy
		True
		>>> cmp = (CmpAny()*3)/CmpRaw()
		>>> cmp == scpy
		True
		'''

		if n > 1:
			return self/CmpAny(field_regex_postfix = self._field_regex_postfix, **self._fields ) * (n - 1)
		else:
			return self

	def __rmul__(self, n):
		'''
		>>> scpy = scapy.Ether()/scapy.IP()/scapy.TCP()/scapy.Raw()
		>>> cmp = CmpEther()/(2*CmpAny())/CmpRaw()
		>>> cmp == scpy
		True
		>>> cmp = 3*CmpAny()/CmpRaw()
		>>> cmp == scpy
		True
		'''

		if n > 1:
			return self/((n - 1) * CmpAny(field_regex_postfix = self._field_regex_postfix, **self._fields ))
		else:
			return self