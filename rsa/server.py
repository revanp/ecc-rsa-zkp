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
    client, client_address = SERVER.accept()
    # print("%s:%s has connected." % client_address)

    return client, client_address

def handle_client(client_sock, client_addresses):
    msg = client_sock.recv(buffer_size)
    msg = json.loads(msg)
    cipher = msg['cipher']
    cipher = cipher.encode('ISO-8859-1')
    datetime = msg['datetime']
    
    # pencatatan(cipher, datetime)
    msg = decrypt(cipher, privKey)
    print(msg)

def pencatatan(msg, dateSend):
	now = str(datetime.now().timestamp())
	f = open('rsa_csv/subscribe_RSA.csv', 'a')
	f.write(msg + ";" + now + ";" + dateSend + "\n")

pubKey, privKey = load_keys()

host = gethostbyname(gethostname())
port = 42000
buffer_size = 2048
address = (host, port)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(address)
SERVER.settimeout(15)
SERVER.listen(1)

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
