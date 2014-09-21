# npdrt

is a (n)etwork (p)acket (d)riven (r)egression (t)esting API.

# abstract

This wrapper offers (hopefully) an easy to use API for creating and running
packet based regression tests. It is done by adding a simple compare function
(including regex matching) and some convenient functions on top on Scapy.
It also uses and adapts Scapys powerful approach to define network packets
and by this it avoids the need for dealing with pcap files when it comes down
to network testing (but of course - you can load and process pcaps to create
tx/rx packets used within the tests).

# rationale

By working on another project (http://freepackets.org) it turned out that testing
a network setup is a very time consuming and boring process. I tried to overcome the
problem using existing tools like NEMESIS, NETCAT and a bunch of pcap-files - but I ended
up with a bunch of messy test scripts that where hard to maintain.

# thanks!

1. phil _at_ secdev.org for scapy (see http://www.secdev.org/projects/scapy/).
2. the guy behind https://isc.sans.edu/diary/TCP+Fuzzing+with+Scapy/14080 for the great idea of using a socket for TCP streams.

# requirements

To be able to use the API you need to install *python 2.x* and *python-scapy* (implies tcpdump).

# principles

Tests are organized in test suites containing a number of test cases. A test case
should only test for one aspect. For this a test case contains a number of tx and rx packets.

Each packet to be send (tx packet) is defined using the Scapy layer primitives and then added to a test cases
tx packet queue. You can add as many packets as you like - they will be send in the order
you added them (yes - you can add packets in a self defined order using the pos attribute) using
the *add_tx_packet()* method.

For each test case a number of expected rx packets can be added. To define these packets you can use the
same layer primitives known from Scapy - just add Cmp in front of the class name:

```
tx packet: Ether()/IP()/TCP()/Raw()
rx packet: CmpEther()/CmpIP()/CmpTCP()/CmpRaw()
```

Every attribute given in the Cmp* layers will be compared to the matching layer in a received
packet. The rx-packets are matched in the order they were added to the rx queue and the matching
process is stopped after the first rx packet matches on all layers (compare packet and received
packet must have the same number and order of layers) and all given attributes must match (attributes present in
the received packet and not given in the Cmp* packet are just ignored).

If a test case only contains tx packets these packets are send and the test case just succeeds.

For each tx packet the network interface the packet should be send over can be specified using one of the following attributes (order defines precedence, 1 overrides 2 and so on):

1. interface parameter of the *add_tx_packet()/add_tx_pcap()* method
2. first src-attribute given in the first layer of the given packet (usually the Ethernet layer)
3. tx_interface attribute of the TestCase
4. tx_interface attribute of the PacketTestSuite

If the socket interface is used to send the packets, the socket configuration (src/dst IP and port) is taken from the first
tx-packet that is added to the test case (limitation: it is currently not possible to send packets via different interfaces within a test case that used the stream socket interface).

For each rx packet the interface the packet must be received over must be given using one of the following attributes (order defines precedence, 1 overrides 2 and so on):

1. interface parameter of the *add_rx_packet()/add_rx_pcap()* method
2. first dst-attribute given in the first layer of the given packet (usually the Ethernet layer)
3. rx_interface attribute of the TestCase
4. rx_interface attribute of the PacketTestSuite

It is possible to stop the matching process after a given layer by adding the *CmpStop()* layer to a CmpLayer packet stack:

```
tx packet: Ether()/IP()/TCP()/Raw()
rx packet: CmpEther()/CmpIP()/CmpStop()
```

The defined rx packet (in the example above) matches the given tx packet. You can also specify the number of times a
rx packet must match before the match is accepted at all by using the count-attribute of the
*add_rx_packet()* method. It is also possible to ignore the type of a layer by using the CmpAny layer:

```
tx packet: Ether()/IP()/TCP()/Raw()
rx packet: CmpAny()/CmpAny()/CmpAny()/CmpRaw()
```

As long as there are 3 layers before *CmpRaw()* every packets matches.

For using regular expressions to compare the attributes of a layer within a packet, the attribute name must use a (configurable)
postfix (default _r). While comparing the attributes the postfix is removed and the content
of the attribute is matched using the given regex (using the python regex style) eg.:

```
tx packet: Ether()/IP(dst='8.8.4.4', ttl=75)/ICMP()
rx packet: CmpEther()/CmpIP(src_r=r'(.)4(.)4$')/CmpICMP()/CmpStop()
```

Note that the stop layer is necessary at this point cause some targets
respond with an ICMP-reply that contains an added raw data layer (layer Raw()) and some just
apply some padding (layer Padding()).

If the packet match criteria is fulfilled (packet(s) where received that matches a rx packet)
before all packets are send, the transmission is stopped. If no rx packets are given, the test
case will just succeed after the last packet was transmitted.

The rx timeout starts after the last tx packets was send. This is a design decision lead by the
idea that every test case may send one or one million packets and the calculation of the
rx timeout based on n tx packets with individual interpacketgaps is not ... very handy.

## examples

More or less each function within the modules contains a doctest section that
should explain how to use it. Have a look at it - its very verbose.

There are also some extended examples in ... examples/. At least for running
tcp-syn-ack-synack-using-pre_run.py and test_case_switch_learning.py some further
configuration/setup is needed (you can find the needed information on that in
the test-files). The general configuration for the test is located in examples/example_settings.py.

