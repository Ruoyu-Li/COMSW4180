import argparse
from scapy.all import *
import random, string

def random_word(length):
	return ''.join([random.choice(string.ascii_letters + string.digits) for n in range(length)])


if __name__ == '__main__':
	# parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("sport", type=int, help="source port")
	parser.add_argument("dport", type=int, help="destination port")
	args = parser.parse_args()
	sport, dport = args.sport, args.dport
	lo = '127.0.0.1'

	# part 1
	for port in range(4001, 4026):
		pkt = IP(src=lo, dst=lo)/TCP(sport=sport, dport=port)
		send(pkt, iface='lo')

	# part 2
	for i in range(5):
		payload = random_word(10)
		pkt = IP(src=lo, dst=lo)/TCP(sport=sport, dport=dport)/Raw(load=payload)
		send(pkt, iface='lo')