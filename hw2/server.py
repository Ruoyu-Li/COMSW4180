# Author: Ruoyu Li
# uni: rl2929

import argparse
import socket
import ssl


if __name__ == '__main__':
	# parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("port", help="port number on which to listen for a connection from the client", type=int)
	parser.add_argument("certificate", help="server's certificate file")
	parser.add_argument("key", help="private key file")
	parser.add_argument("ca", help="ca certificate")
	args = parser.parse_args()
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
		print("server's certificate doesn't exist or wrong file name.")
		exit(1)
	# check key file exist
	try:
		f = open(key)
		f.close()
	except IOError:
		print("server's private key doesn't exist or wrong file name.")
		exit(1)
	# check ca certificate exist
	try:
		f = open(ca)
		f.close()
	except IOError:
		print("ca certificate doesn't exist or wrong file name.")
		exit(1)	

	# open a socket and listen to the port, waiting for connection
	bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_addr = (socket.gethostbyname(socket.gethostname()), port)
	bindsocket.bind(server_addr)
	print("start listening on %s %s" % server_addr)
	bindsocket.listen(5)

	recv = b''	
	print("waiting for a connection...")
	try:
		# create a new socekt to transmit data
		newsocket, client_addr = bindsocket.accept()
		print("connection from %s %s" % client_addr)
		# TLS wrapper
		connstream = ssl.wrap_socket(newsocket,
						server_side=True,
						certfile=certificate,
						cert_reqs=ssl.CERT_REQUIRED,
						keyfile=key,
						ca_certs=ca,
						ssl_version=ssl.PROTOCOL_TLSv1
						)
		while True:
			data = connstream.recv(16)
			if data:
				recv += data
			else:
				print("no more data from %s %s" % client_addr)
				break
		with open("file_from_client.txt", "wb") as f:
			f.write(recv)
	except KeyboardInterrupt:
		# ctrl + c termination
		print("\nserver closed")
	except ssl.SSLError:
		print("ssl socket cannot establish, please check parameters and certificates")
	except ConnectionRefusedError:
		print("cannot connect with client")
	except ConnectionResetError:
		print("connection reset by peer")	
	finally:
		# clear up
		try:
			connstream.close()
		except NameError:
			pass
				





