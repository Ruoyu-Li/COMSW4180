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


def load_client_rsa_key(filename):
	# return client's key pair
	with open(filename, "rb") as priv:
		lines = priv.read()
	private_key = load_pem_private_key(lines, None, backend)
	public_key = private_key.public_key()
	return private_key, public_key


def load_server_rsa_key(filename):
	# return server's public key
	with open(filename, "rb") as pub:
		lines = pub.read()
	public_key = load_pem_public_key(lines, backend)
	return public_key


def derive_key(pwd, salt):
	# derive secret key by password
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=100000,
		backend=backend
	)
	buf = kdf.derive(pwd)
	return buf[:16], buf[16:]


def aes_encrypt(key, IV, ptext):
	# pad plaintext
	pad = padding.PKCS7(128).padder()
	ptext = pad.update(ptext) + pad.finalize()

	# create an encryptor
	alg = algorithms.AES(key)
	mode = modes.CBC(IV)
	cipher = Cipher(alg, mode, backend=backend)
	encryptor = cipher.encryptor()

	# encrypt plain text
	ctext = encryptor.update(ptext) + encryptor.finalize()

	# encode base64
	return ctext


def encrypt_file(filename, rsa_key, password):
	# encrypt a file by symmetric key and encrypt the key by rsa public key
	salt = os.urandom(8)
	pwd = password.encode()
	key, IV = derive_key(pwd, salt)
	with open(filename, "rb") as f:
		ptext = f.read()
		ctext = aes_encrypt(key, IV, ptext)
	ctext = IV + ctext

	# encrypt symmetric key
	public_key = load_server_rsa_key(rsa_key)
	cipher_key = public_key.encrypt(
		key,
		rsa_padding.OAEP(
			mgf=rsa_padding.MGF1(algorithm=hashes.SHA1()),
			algorithm=hashes.SHA1(),
			label=None
		)
	)
	return cipher_key + ctext


def sign_file(filename, rsa_key):
	# sign a file by rsa private key
	with open(filename, "rb") as f:
		ptext = f.read()
	private_key, public_key = load_client_rsa_key(rsa_key)
	signature = private_key.sign(
		ptext,
		rsa_padding.PSS(
			mgf=rsa_padding.MGF1(hashes.SHA256()),
			salt_length=rsa_padding.PSS.MAX_LENGTH
		),
		hashes.SHA256()
	)
	return signature, ptext


if __name__ == '__main__':
	# parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("password", help="password to generate a key")
	parser.add_argument("filename", help="path of the file")
	parser.add_argument("action", help="one of a, b, c")
	parser.add_argument("ip", help="server's ip address")
	parser.add_argument("port", help="port number", type=int)
	parser.add_argument("private_key", help="client's private key file")
	parser.add_argument("public_key", help="server's public key file")
	args = parser.parse_args()

	password, filename, action = args.password, args.filename, args.action
	ip, port = args.ip, args.port
	private_key, public_key = args.private_key, args.public_key

	# input checking
	if len(password) < 16:
		print("The length of password should be at least 16")
		exit(1)
	try:
		f = open(filename)
		f.close()
	except IOError:
		print("The file doesn't exist")
		exit(1)
	if action not in ['a', 'b', 'c']:
		print("Action should only be one of a, b, c")
		exit(1)
	if port < 0 or port > 65535:
		print("Port should only be between 0 and 65535")
		exit(1)

	# check if key pair doesn't exist
	try:
		f = open(private_key)
		f.close()
	except IOError:
		print("client's private key doesn't exist or wrong file name.\nYou should generate it firstly by:\npython3 rsa_keys.py [filename]")
		exit(1)
	try:
		f = open(public_key)
		f.close()
	except IOError:
		print("server's public key doesn't exist or wrong file name.\nYou should ask the server for its public key.")
		exit(1)

	# encrypt a file and key
	if action == 'a':
		message = encrypt_file(filename, public_key, password)

	# sign a file
	elif action == 'b':
		signature, ptext = sign_file(filename, private_key)
		message = signature + ptext

	# sign a modified file
	elif action == 'c':		
		signature, ptext = sign_file(filename, private_key)
		if ptext[0] != '\x00':
			replace = b'\x00'
		else:
			replace = b'\xFF'
		ptext = replace + ptext[1:]
		message = signature + ptext

	# send message through socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_address = (ip, port)
	try:
		sock.connect(server_address)
		print("send data to %s %s..." % server_address)
		sock.sendall(message)
	except ConnectionRefusedError:
		print("server is closed")
	finally:
		sock.close()

