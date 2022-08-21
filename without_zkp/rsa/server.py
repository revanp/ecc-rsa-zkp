from socket import *
from threading import Thread
from datetime import datetime

import rsa
import time
import json

def load_keys():
    with open('rsa_key/pubkey.pem', 'rb') as f:
        pubKey = rsa.PublicKey.load_pkcs1(f.read())

    with open('rsa_key/privkey.pem', 'rb') as f:
        privKey = rsa.PrivateKey.load_pkcs1(f.read())

    return pubKey, privKey

def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False

def accept_incoming():
    client, client_address = server.accept()
    print("%s:%s has connected." % client_address)

    return client, client_address

def handle_client(client_sock, client_addresses):
    msg = client_sock.recv(buffer_size)
    msg = decrypt(msg, privKey)
    print(msg)

pubKey, privKey = load_keys()

host = 'localhost'
# host = gethostbyname(gethostname())
port = 42000
buffer_size = 3072
address = (host, port)

server = socket(AF_INET, SOCK_STREAM)
server.bind(address)
server.settimeout(15)
server.listen(1)

print('Server IP: ', host)
print("Waiting for connection...")

stopped = False
while not stopped:
    try: 
        client, client_address = accept_incoming()
    except:
        stopped = True
        print('Timeout')
    else:
        handle_client(client, client_address)
