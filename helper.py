
class UniqueId(object):
	'''generate an application wide unique numeric id
	
	>>> UniqueId().id,UniqueId().id,UniqueId().id
	(0, 1, 2)
	'''

	_gid = 0

	def __init__(self):
		self._id = UniqueId._gid
		UniqueId._gid = UniqueId._gid + 1

	@property
	def id(self):

		return self._id

def insert_at(vlist, pos = None, var = None):
	''' insert an element in the given position to the list and return the position.

	if pos is None, the element is appended to the list.

	return:
	index the element was inserted : int

	>>> l = []
	>>> idx = insert_at(l); print(idx)
	0
	>>> idx = insert_at(l); print(idx)
	1
	>>> idx = insert_at(l); print(idx)
	2
	>>> idx = insert_at(l, pos=-10); print(idx)
	0
	>>> idx = insert_at(l, pos=10); print(idx)
	4
	>>> idx = insert_at(l, pos=3); print(idx)
	3
	>>> idx = insert_at(l, pos=-5); print(idx)
	1
	>>> idx = insert_at(l, pos=-7); print(idx)
	0
	>>> idx = insert_at(l, pos=-8); print(idx)
	0
	>>> idx = insert_at(l); print(idx)
	9
	'''

	if not isinstance(vlist, list):
		raise TypeError('given list is not an instance of type list.')

	if pos is None:
			vlist.append(var)	
			return len(vlist) - 1

	vlist.insert(pos, var)
	if pos >= 0: 
		return pos if pos < len(vlist) else (len(vlist) - 1)
	else:
		return 0 if abs(pos) >= len(vlist) else ((len(vlist) + pos) - 1)


def scapy_tcp_flags(value):
	'''converts scapy TCP flags from string to number and vice versa

	the following flag-to-character encoding is used:
	F - FIN
	S - SEQ
	R - RST
	P - PSH
	A - ACK
	U - URG
	E - ECN-Echo
	C - Congestion Window Reduced

	arguments:
	value -- contains either a number (0..255) or a string containing a combination of the characters 'FSRPAUEC'

	return:
	the number (0..255) representing the given string as TCP flag or 
	the string build using 'FSRPAUEC' representing the given number as TCP flag

	>>> d = {'F':1, 'S':2, 'R':4, 'P':8, 'A':16, 'U':32, 'E':64, 'C':128, 'SA': 18, 'SA':0x12}

	>>> [scapy_tcp_flags(key) == d[key] for key in d]
	[True, True, True, True, True, True, True, True, True]

	>>> [scapy_tcp_flags(d[key]) == key for key in d]
	[True, True, True, True, True, True, True, True, True]

	'''

	flag_bit_to_char = 'FSRPAUEC'
	
	try:
		flag_num = int(value)

	except ValueError:

		flag_num = 0
		flag_str = value.upper()

		for c in list(flag_str):
			if c not in flag_bit_to_char:
				raise ValueError('given TCP flag value contains invalid character (must be in [FSRPAUEC])')

		for i,c in enumerate(flag_bit_to_char):
			if c in flag_str:
				flag_num = flag_num | (1<<i)

		return flag_num

	if flag_num < 0 or flag_num > 255:
		raise ValueError('given TCP flag value is out of range (must be 0..255)')
	flag_str = ''
	for i,c in enumerate(flag_bit_to_char):
		if flag_num & (1<<i) != 0:
			flag_str = flag_str + c

	return flag_str
