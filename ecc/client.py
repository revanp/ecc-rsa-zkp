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

def load_keys():
    with open('ecc_key/pubkey.pem', 'r') as f:
        pubKey = f.read()

    with open('ecc_key/privkey.pem', 'r') as f:
        privKey = f.read()

    return pubKey, privKey

def encryptText(msg, key):
    return encrypt(key, msg)

pubKey, privKey = load_keys()

HOST = input('Enter host: ')
PORT = int(input('Enter port: '))
BUFFER_SIZE = 1024
ADDRESS = (HOST, PORT)

CLIENT = socket(AF_INET, SOCK_STREAM)
CLIENT.connect(ADDRESS)

msg = b"Brigitha"
ciphertext = encryptText(msg, pubKey)

CLIENT.send(bytes(ciphertext))

print(ciphertext)