from socket import *
from threading import Thread
from noknow.core import ZK, ZKSignature, ZKParameters, ZKData, ZKProof
from queue import Queue
from datetime import datetime

from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
import random
import time

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
    return encrypt(key, msg.encode('ascii'))

pubKey, privKey = load_keys()

# host = '192.168.100.174'
host = gethostbyname(gethostname())
port = 42001
buffer_size = 2048
address = (host, port)

for i in range(1): 
    zk = ZK.new(curve_name = "secp256k1", hash_alg = "sha3_256")

    client = socket(AF_INET, SOCK_STREAM)
    client.connect(address)

    # msg = str(random.randint(0, 10))
    msg = input('Enter message: ')
    signature = zk.create_signature(msg)
    ciphertext = encryptText(signature.dump(), pubKey)
    now = str(datetime.now().timestamp())

    client.send(bytes(ciphertext))

    token = client.recv(buffer_size).decode('utf-8')
    proofInput = input('Enter again: ')
    # proofInput = str(random.randint(0, 10))
    proof = zk.sign(proofInput, token).dump()

    client.send(bytes(proof, 'utf-8'))

    response = client.recv(buffer_size).decode('utf-8')
    print(response)
