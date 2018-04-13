from scapy.all import *
import argparse
import socket


if __name__ == '__main__':
	# parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("input", help="name of the file to analyze")
	args = parser.parse_args()
	input_file = args.input

	# parse input file
	with open(input_file, 'r') as f:
		src = f.readline()
		dst = f.readline()
		sport = f.readline()
		dport = f.readline()
		get = f.readline()

	# establish TCP handshank, start from SYN packet
	syn = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags='S')
	ans = sr1(syn)
	print(ans.show())
	# send packet with HTTP request message
	request=IP(src=src, dst=dst)/TCP(dport=dport, sport=ans[TCP].dport, seq=ans[TCP].ack, ack=ans[TCP].seq + 1, flags='A')/Raw(load=get)
	ans = sr1(syn)
	print(ans.show())