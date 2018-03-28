# Author: Ruoyu Li
# uni: rl2929

import argparse
import socket
import ssl


if __name__ == '__main__':
	# parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("filename", help="name of file to be sent to the server")
	parser.add_argument("ip", help="IP address on which to contact the server")
	parser.add_argument("port", help="port number on which to contact the server", type=int)
	parser.add_argument("certificate", help="server's certificate file")
	parser.add_argument("key", help="private key file")
	parser.add_argument("ca", help="ca certificate")
	args = parser.parse_args()
	filename, ip = args.filename, args.ip
	port, certificate, key, ca = args.port, args.certificate, args.key, args.ca

	# check port is legitimate
	if port < 0 or port > 65535:
		print("Port should only be between 0 and 65535")
		exit(1)
	# check certificate file
	try:
		f = open(certificate)
		f.close()
	except IOError:
		print("client's certificate doesn't exist or wrong file name.")
		exit(1)
	# check key file exist
	try:
		f = open(key)
		f.close()
	except IOError:
		print("client's private key doesn't exist or wrong file name.")
		exit(1)
	# check the file to send
	try:
		f = open(filename, 'rb')
		send = f.read()
		f.close()
	except IOError:
		print("file doesn't exist or wrong file name")
		exit(1)
	# check ca certificate exist
	try:
		f = open(ca)
		f.close()
	except IOError:
		print("ca certificate doesn't exist or wrong file name.")
		exit(1)	
		
	try:
		# socket connection
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# TLS wrapper
		ssl_socket = ssl.wrap_socket(s,
						certfile=certificate,
						cert_reqs=ssl.CERT_REQUIRED,
						keyfile=key,
						ca_certs=ca,
						ssl_version=ssl.PROTOCOL_TLSv1
						)
		server_addr = (ip, port)
		ssl_socket.connect(server_addr)
		print("send data to %s %s" % server_addr)
		ssl_socket.write(send)
	except ConnectionRefusedError:
		print("server is closed")
	except ConnectionResetError:
		print("connection reset by peer")
	except ssl.SSLError:
		print("ssl socket cannot establish")
	finally:
		ssl_socket.close()







