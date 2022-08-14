from socket import *
from threading import Thread

from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt

def generate_keys():
    key = generate_eth_key()

    privKey = key.to_hex()
    pubKey = key.public_key.to_hex()
    with open('ecc_key/pubkey.pem', 'w') as f:
        f.write(pubKey)

    with open('ecc_key/privkey.pem', 'w') as f:
        f.write(privKey)

generate_keys()

# plaintext = b"Brigitha"
# encrypted = encrypt(pk_hex, plaintext)

# print(encrypted)

