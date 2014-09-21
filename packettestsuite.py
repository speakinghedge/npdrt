from testcase import *
import collections
from helper import *
import time

class PacketTestSuite(UniqueId):

	'''acts as a container and runner for test cases
	'''

	def __init__(self, name = None, rx_interface = None, tx_interface = None):
		''' create a new packet test suite

		arguments:
		name -- name of the test suite (default: anonymous)
		rx_interface -- if given, used as default rx_interface for test cases
		tx_interface -- if given, used as default tx_interface for test cases

		>>> PacketTestSuite().id, PacketTestSuite().id, PacketTestSuite().id
		(0, 1, 2)

		>>> PacketTestSuite('foo').name
		'foo'

		>>> PacketTestSuite().name
		'anonymous'
		'''

		super(PacketTestSuite, self).__init__()
		self._name = name if name is not None else 'anonymous'
		self._current_test_case = None
		self._test_cases = []
		self._test_case_num = 0
		self._rx_interface = rx_interface
		self._tx_interface = tx_interface
		
	@property
	def name(self):
		return self._name

	@property
	def current_test_case(self):
		return self._current_test_case

	def add_test_case(self, name = None, pos = None, intertestcasegap = 0, interpacketgap = 0, timeout = 1000, rx_interface = None, tx_interface = None, pre_run_processing = None):
		'''add a new test case to the test suite.

		arguments:
		name -- name of the test case (default: auto generated)
		pos -- position in the list of test cases the new test should be inserted on (default: append to list)
		intertestcasegap -- time in milliseconds between two test cases (default: 0)
		interpacketgap -- default value for the time between two transmitted packets in milliseconds (default: 0)
		timeout -- default value for the maximum time to be waited for a received packet after the last packet was send in milliseconds (default: 1000)
		rx_interface -- if given, used as default rx_interface if there is no other interface selector given for a rx-packet
		tx_interface -- if given, used as default rx_interface if there is no other interface selector given for a tx-packet
		pre_run_processing -- callable foo(cmp_packet, rx_packet), first function executed by the run-method (default: None)

		return:
		(testcase, index, id) -- testcase instance, index of the test case in the list of test cases, identifier of the test case
		
		>>> pts = PacketTestSuite(); 
		>>> tc, idx = pts.add_test_case()
		>>> tc, idx = pts.add_test_case(name='foo'); print(tc.name)
		foo
		>>> tc, idx = pts.add_test_case(name='bar'); print(tc.name)
		bar
		>>> tc, idx = pts.add_test_case(name='baz', interpacketgap=42, timeout=23); print(tc.name, tc.interpacketgap, tc.timeout)
		('baz', 42, 23)
		'''

		# no local interface selection -> used global selection
		if rx_interface is None:
			rx_interface = self._rx_interface

		if tx_interface is None:
			tx_interface = self._tx_interface
		
		tc = TestCase(name = name, intertestcasegap = intertestcasegap, interpacketgap = interpacketgap, timeout = timeout, rx_interface = rx_interface, tx_interface = tx_interface, pre_run_processing = pre_run_processing)
		self._current_test_case = tc

		return tc, insert_at(self._test_cases, pos, tc)

	def get_test_case(self, id):

		'''return the test case (and its position in the list of the test cases) selected by the given id.

		arguments:
		id -- identifier of the testcase to be returned

		return:
		(testcase, index) -- testcase instance, index of the test case in the list of test cases

		>>> pts = PacketTestSuite(); tc, idx = pts.add_test_case(); tc_b = pts.get_test_case(tc.id);
		>>> tc, idx = pts.add_test_case(-1); tc_b = pts.get_test_case(tc.id);
		'''

		idx = 0
		for tc in self._test_cases:
			if tc.id == id :
				return tc, idx
			idx = idx + 1 

		raise LookupError('testcase with id %d not found.' % (id))

	def remove_test_case(self, id):
		'''remove a testcase selected by id from the test cases list.

		arguments:
		id -- identifier of the testcase to be removed

		return:
		number of remaining test cases in the list

		>>> pts = PacketTestSuite()
		>>> tc0, idx = pts.add_test_case()
		>>> tc1, idx = pts.add_test_case() 
		>>> tc2, idx = pts.add_test_case()
		>>> pts.remove_test_case(tc1.id)
		2
		'''

		tc, idx = self.get_test_case(id)
		self._test_cases.pop(idx)

		return len(self._test_cases)


	def run(self, verbose = None, id = None):
		'''execute test cases within the suite. 

		arguments:
		verbose -- show additional output (default: None - no output)
		id -- id or list of ids of test cases to be executed
		
		return:
		(total, success, fail) -- total number of test cases executed, successfully executed test cases, failed test cases
		
		>>> pts = PacketTestSuite()
		>>> tc0, idx = pts.add_test_case('foo')
		>>> tc1, idx = pts.add_test_case('bar')
		
		>>> pts.run()
		(2, 2, 0)
		
		>>> pts.run(id=tc1.id)
		(1, 1, 0)
		
		>>> pts.run(id=tc0.id)
		(1, 1, 0)
		
		>>> tc2, idx = pts.add_test_case('baz')
		>>> pts.run(id=(tc0.id, tc2.id))
		(2, 2, 0)
		
		>>> pts.run(id=-1)
		(0, 0, 0)
		'''

		if verbose == True:
			print('test suite: %s' %(self._name))

		executed, succeeded, failed = 0, 0, 0
		itcg = 0
		for test_case in self._test_cases:
			
			time.sleep(itcg/1000.)
			itcg = 0

			if ( (id is not None and (test_case.id == id or (isinstance(id, collections.Iterable) and test_case.id in id))) or id is None):
				executed = executed + 1
				succeeded, failed = ((succeeded + 1), failed) if True == test_case.run(verbose) else (succeeded, (failed + 1))
				itcg = test_case.intertestcasegap
		
		return executed, succeeded, failed
