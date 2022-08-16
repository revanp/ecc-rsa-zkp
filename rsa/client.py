from socket import *
from threading import Thread
from noknow.core import ZK, ZKSignature, ZKParameters, ZKData, ZKProof
from getpass import getpass
from queue import Queue
from datetime import datetime

import rsa 
import random
import time
import json

def generate_keys():
    (pubKey, privKey) = rsa.newkeys(2048)
    with open('rsa_key/pubkey.pem', 'wb') as f:
        f.write(pubKey.save_pkcs1('PEM'))

    with open('rsa_key/privkey.pem', 'wb') as f:
        f.write(privKey.save_pkcs1('PEM'))

def load_keys():
    with open('rsa_key/pubkey.pem', 'rb') as f:
        pubKey = rsa.PublicKey.load_pkcs1(f.read())

    with open('rsa_key/privkey.pem', 'rb') as f:
        privKey = rsa.PrivateKey.load_pkcs1(f.read())

    return pubKey, privKey

def encrypt(msg, key):
    return rsa.encrypt(msg.encode('ascii'), key)

def pencatatan(i, waktu):
    f = open('rsa_csv/publish_RSA.csv', 'a')
    f.write("Pesan ke-" + i + ";" + msg + ";" + waktu + "\n")

pubKey, privKey = load_keys()

HOST = '192.168.100.174'
PORT = 42000
ADDRESS = (HOST, PORT)

message = {}
for i in range(10): 
    CLIENT = socket(AF_INET, SOCK_STREAM)
    CLIENT.connect(ADDRESS)

    msg = str(random.randint(0, 1000))
    ciphertext = encrypt(msg, pubKey)
    now = str(datetime.now().timestamp())

    pencatatan(str(i), now)
    message['cipher'] = ciphertext.decode('ISO-8859-1')
    message['datetime'] = now

    jsonToString = json.dumps(message, indent=2)

    print(jsonToString + "\n")
    CLIENT.send(bytes(jsonToString, encoding = 'utf-8'))
