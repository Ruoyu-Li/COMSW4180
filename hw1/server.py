import argparse
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import sys
import socket


backend = default_backend()


def load_server_rsa_key(filename):
	# return server's key pair
	with open(filename, "rb") as priv:
		lines = priv.read()
	private_key = load_pem_private_key(lines, None, backend)
	public_key = private_key.public_key()
	return private_key, public_key


def load_client_rsa_key(filename):
	# return client's public key
	with open(filename, "rb") as pub:
		lines = pub.read()
	public_key = load_pem_public_key(lines, backend)
	return public_key


def aes_decrypt(key, IV, ctext):
	alg = algorithms.AES(key)
	mode = modes.CBC(IV)
	cipher = Cipher(alg, mode, backend=backend)
	decryptor = cipher.decryptor()
	ptext = decryptor.update(ctext) + decryptor.finalize()

	unpadder = padding.PKCS7(128).unpadder() # 128 bit
	ptext = unpadder.update(ptext) + unpadder.finalize()
	return ptext


def decrypt_file(message, rsa_key):
	# decrypt the symmetric key by private key and decrypt the file by symmetic key
	cipher_key = message[:256]
	ctext = message[256:]

	# decrypt symmetric key
	private_key, public_key = load_server_rsa_key(rsa_key)
	key = private_key.decrypt(
		cipher_key,
		rsa_padding.OAEP(
			mgf=rsa_padding.MGF1(algorithm=hashes.SHA1()),
			algorithm=hashes.SHA1(),
			label=None
		)
	)

	#decryp file
	IV = ctext[:16]
	ctext = ctext[16:]
	ptext = aes_decrypt(key, IV, ctext)
	print("decrypte file successfully")
	with open("decrypted_file.txt", "wb") as f:
		f.write(ptext)


def verify_signature(message, rsa_key):
	# verify a signature by public key
	signature = message[:256]
	ptext = message[256:]

	public_key = load_client_rsa_key(rsa_key)
	try:
		public_key.verify(
			signature,
			ptext,
			rsa_padding.PSS(
				mgf=rsa_padding.MGF1(hashes.SHA256()),
				salt_length=rsa_padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)
		print("signature is valid")
	except Exception:
		print("signature is invalid")


if __name__ == '__main__':
	# parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("port", help="port number", type=int)
	parser.add_argument("mode", help="d means it will be decrypting a file, v means it will be verifying a signature")
	parser.add_argument("private_key", help="server's private key file")
	parser.add_argument("public_key", help="client's public key file")	
	args = parser.parse_args()

	port, mode = args.port, args.mode
	private_key, public_key = args.private_key, args.public_key

	# input checking
	if port < 0 or port > 65535:
		print("Port should only be between 0 and 65535")
		exit(1)
	if mode not in ['d', 'v']:
		print("Mode should only be either d and v")
		exit(1)
	if ".pub" not in public_key:
		print("public key file should be a format of .pub")
		exit(1)

	# check if key pair doesn't exist
	try:
		f = open(private_key)
		f.close()
	except IOError:
		print("server's private key doesn't exist or wrong file name.\nYou should generate it firstly by:\npython3 rsa_keys.py [filename]")
		exit(1)
	try:
		f = open(public_key)
		f.close()
	except IOError:
		print("client's public key doesn't exist or wrong file name.\nYou should ask the client for its public key.")
		exit(1)

	# listening socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_address = ('localhost', port)
	print("starting up on %s %s" % server_address)
	sock.bind(server_address)
	sock.listen(1)

	message = b''
	print("waiting for a connection...")
	try:
		connection, client_address = sock.accept()
		print("connection from %s %s" % client_address)
		# receive the data in small chunks and retransmit it
		while True:
			data = connection.recv(16)
			if data:
				print("received %s" % data)
				message += data
			else:
				print("no more data from %s %s" % client_address)
				break
		# do server's work
		if mode == 'd':
			decrypt_file(message, private_key)
		elif mode == 'v':
			verify_signature(message, public_key)
		message = b''
	except KeyboardInterrupt:
		print('\nserver closed')
	finally:
		# clean up the connection
		try:
			connection.close()
		except NameError:
			pass


