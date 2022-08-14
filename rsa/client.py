from socket import *
from threading import Thread
from noknow.core import ZK, ZKSignature, ZKParameters, ZKData, ZKProof
from getpass import getpass
from queue import Queue

import rsa
import random
import time

def generate_keys():
    (pubKey, privKey) = rsa.newkeys(2048)
    with open('rsa_key/pubkey.pem', 'wb') as f:
        f.write(pubKey.save_pkcs1('PEM'))

    with open('rsa_key/privkey.pem', 'wb') as f:
        f.write(privKey.save_pkcs1('PEM'))

def send(event = None):
    CLIENT.send(bytes(msg, "utf8"))

def load_keys():
    with open('rsa_key/pubkey.pem', 'rb') as f:
        pubKey = rsa.PublicKey.load_pkcs1(f.read())

    with open('rsa_key/privkey.pem', 'rb') as f:
        privKey = rsa.PrivateKey.load_pkcs1(f.read())

    return pubKey, privKey

def encrypt(msg, key):
    return rsa.encrypt(msg.encode('ascii'), key)

def sign_sha1(msg, key):
    return rsa.sign(msg.encode('ascii'), key, 'SHA-1')

def verify_sha1(msg, signature, key):
    try:
        return rsa.verify(msg.encode('ascii'), signature, key) == 'SHA-1'
    except:
        return False

pubKey, privKey = load_keys()

HOST = input('Enter host: ')
PORT = int(input('Enter port: '))
BUFFER_SIZE = 2048
ADDRESS = (HOST, PORT)

CLIENT = socket(AF_INET, SOCK_STREAM)
CLIENT.connect(ADDRESS)

msg = str(random.randint(0, 1000))
ciphertext = encrypt(msg, pubKey)
signature = sign_sha1(msg, privKey)

print(msg)

CLIENT.send(bytes(signature))

# print(f'Cipher text: {ciphertext}')
# m = CLIENT.recv(BUFFER_SIZE).decode('utf8')