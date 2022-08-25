from socket import *
from threading import Thread
from noknow.core import ZK, ZKSignature, ZKParameters, ZKData, ZKProof
from queue import Queue
from datetime import datetime

from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
import random
import time
import sys

def generate_keys():
    key = generate_eth_key()

    privKey = key.to_hex(160)
    pubKey = key.public_key.to_hex(160)
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

host = 'localhost'
# host = gethostbyname(gethostname())
port = 42001
buffer_size = 2048
address = (host, port)

memory_usage = 0
for i in range(1):
    zk = ZK.new(curve_name = "secp256k1", hash_alg = "sha3_256")

    client = socket(AF_INET, SOCK_STREAM)
    client.connect(address)

    # msg = str(random.randint(0, 10))
    msg = input('Enter message: ')
    signature = zk.create_signature(msg)
    ciphertext = encryptText(signature.dump(), pubKey)
    now = str(datetime.now().timestamp())

    # AVALANCHE
    msg_bin = int.from_bytes(signature.dump().encode('ascii'), byteorder = sys.byteorder)
    ciphertext_bin = int.from_bytes(ciphertext, byteorder = sys.byteorder)

    diff = bin(msg_bin ^ ciphertext_bin)

    count = 0
    for j in diff:
        if j == "1":
            count += 1
            # print ("Total difference \t:\t", count, "bits")

        len_a = len(bin(msg_bin))
        len_b = len(bin(ciphertext_bin))

    if (len_a) >= (len_b):
        AE = (count/ len_a) * 100
    else:
        AE = (count/ len_b) * 100
    # END AVALANCHE

    # MEMORY
    memory_usage += sys.getsizeof(ciphertext)
    # END MEMORY

    client.send(bytes(ciphertext))

    token = client.recv(buffer_size).decode('utf-8')
    proofInput = input('Enter again: ')
    # proofInput = str(random.randint(0, 10))
    proof = zk.sign(proofInput, token).dump()

    client.send(bytes(proof, 'utf-8'))

    response = client.recv(buffer_size).decode('utf-8')

    print("\n----------------------------------------------")
    print(response)
    print("----------------------------------------------")
    print ("Avalanche effect \t:\t", AE, "%")
    print("Used memory : ", (memory_usage / 1000), "Kb")
