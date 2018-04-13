from scapy.all import *
import argparse
import socket


if __name__ == '__main__':
	# parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("input", help="name of the file to analyze")
	args = parser.parse_args()
	input_file = args.input

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_address = ('127.0.0.1', 8000)
	try:
		sock.connect(server_address)
		print("success")
		while 1:
			pass
	except ConnectionRefusedError:
		print("server is closed")
	finally:
		sock.close()

	# packet = IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=9999,dport=8000)/Raw(load='GET / HTTP/1.1')
