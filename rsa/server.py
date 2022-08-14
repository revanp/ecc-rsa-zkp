from socket import *
from threading import Thread
import rsa
import time

client_sock = []
client_addresses = {}
public_key = []

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

def verify_sha1(msg, signature, key):
    try:
        return rsa.verify(msg.encode('ascii'), signature, key) == 'SHA-1'
    except:
        return False

def accept_incoming(): 
    client, client_address = SERVER.accept()
    client_sock.append(client)
    print("%s:%s has connected." % client_address)
    client_addresses[client] = client_address

def handle_client(client_sock, client_addresses):
    signature = client_sock[0].recv(BUFFER_SIZE)
    message = input('Input text:')
    
    if(verify_sha1(message, signature, pubKey)):
        print('Verified!')
    else:
        print('Not match!')

pubKey, privKey = load_keys()

HOST = gethostbyname(gethostname())
PORT = 42000
BUFFER_SIZE = 1024
ADDRESS = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDRESS)

SERVER.listen(2)
print('Server IP: ', HOST)
print("Waiting for connection...")
accept_incoming()

Thread(target = handle_client, args = (client_sock, client_addresses)).start()

SERVER.close()