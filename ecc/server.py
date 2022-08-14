from socket import *
from threading import Thread
from ecies import encrypt, decrypt

client_sock = []
client_addresses = {}
public_key = []

def load_keys():
    with open('ecc_key/pubkey.pem', 'r') as f:
        pubKey = f.read()

    with open('ecc_key/privkey.pem', 'r') as f:
        privKey = f.read()

    return pubKey, privKey

def accept_incoming(): 
    client, client_address = SERVER.accept()
    client_sock.append(client)
    print("%s:%s has connected." % client_address)
    client_addresses[client] = client_address

def handle_client(client_sock, client_addresses):
    message = client_sock[0].recv(BUFFER_SIZE)
    message = decrypt(privKey, message)

    print(message)

pubKey, privKey = load_keys()

HOST = gethostbyname(gethostname())
PORT = 42001
BUFFER_SIZE = 2048
ADDRESS = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDRESS)

SERVER.listen(2)
print('Server IP: ', HOST)
print("Waiting for connection...")
accept_incoming()

Thread(target = handle_client, args = (client_sock, client_addresses)).start()

SERVER.close()