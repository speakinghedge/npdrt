#!/bin/bash

delim() {
	echo
	echo '************************************************************'
	echo
}

# create a test case sending ICMP echo request to 8.8.8.8
sudo python -m examples.create_test_case

delim
# just create a test suite containing a test case sending ICMP echo request to 8.8.8.8
sudo python -m examples.create_test_suite

delim
# load pcap, delete MAC addresses and add to rx and tx list
python -m examples.test_case_load_pcap_tx_preprocessing

delim
# load pcap, delete MAC addresses and add to rx and tx list
python -m examples.test_case_load_pcap_rx_tx_simple

delim
# test switch behavior - learning MAC addresses
# sudo python -m examples.test_case_switch_learning

delim
# send ICMP echo request to 8.8.8.8
sudo python -m examples.test_case_ping_8_8_8_8

delim
# send ICMP echo request to 8.8.4.4, use regex to match received packets
sudo python -m examples.test_case_ping_8_8_4_4_regex_match

delim
# use TCP via hand crafted connection setup (using pre runner functions to generate seq/ack-numbers)
# to be able to run the test, you must first run 
# sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <your source interfaces IP>  -j DROP
# see examples/tcp-syn-ack-synack-using-pre_run.py for further information
# sudo python -m examples.tcp-syn-ack-synack-using-pre_run

delim
# use TCP connection via stream socket (http-get on google)
sudo python -m examples.tcp-via-socket