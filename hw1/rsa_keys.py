import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding


backend = default_backend()


def generate_rsa_key():
	# generate rsa key pair
	key = rsa.generate_private_key(
	    backend=backend,
	    public_exponent=65537,
	    key_size=2048
	)
	return key


def save_rsa_key(key, name):
	# save private key as *_rsa
	private_key = key.private_bytes(
	    crypto_serialization.Encoding.PEM,
	    crypto_serialization.PrivateFormat.TraditionalOpenSSL,
	    crypto_serialization.NoEncryption()
    )
	with open(name, "wb") as priv:
	    priv.write(private_key)

    # save public key as *_rsa.pub
	public_key = key.public_key().public_bytes(
	    crypto_serialization.Encoding.PEM,
	    crypto_serialization.PublicFormat.SubjectPublicKeyInfo
	)
	with open(name + ".pub", "wb") as pub:
	    pub.write(public_key)


if __name__ == '__main__':
	# parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("filename", help="file name of rsa key pair(xxx for private key, xxx.pub for public key)")
	args = parser.parse_args()
	filename = args.filename

	if len(filename) > 255:
		print("length of file name is too long")
		exit(1)
	try:
		key = generate_rsa_key()
		save_rsa_key(key, filename)
		print("generate rsa key pair successfully")
	except Exception:
		print("fail to generate rsa key pair")
		exit(1)

