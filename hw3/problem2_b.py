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

	# establish TCP handshank, start from SYN packet
	syn = IP(dst='10.142.0.3')/TCP(dport=8000, flags='S')
	ans = sr1(syn)
	print(ans)
	request=IP(dst='10.142.0.3')/TCP(dport=8000, sport=ans[TCP].dport, seq=ans[TCP].ack, ack=ans[TCP].seq + 1, flags='A')/Raw(load='GET / HTTP/1.1\r\nHost: 10.142.0.3:8000\r\n')
	ans = sr1(syn)
	print(ans)