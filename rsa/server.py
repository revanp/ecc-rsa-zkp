from socket import *
from threading import Thread
import rsa

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

def accept_incoming(): 
    client, client_addresses = SERVER.accept()
    client_sock.append(client)
    print("%s:%s has connected." % client_addresses)

def handle_client(client_sock, client_addresses):
    msg0 = client_sock[0].recv(BUFFER_SIZE)
    msg1 = decrypt(msg0, privKey)
    print(" Client : %s" % msg1)

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
# print('From user: ')
SERVER.close()