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

def decryptText(ciphertext, key):
    try:
        return decrypt(key, ciphertext).decode('ascii')
    except:
        return False

def accept_incoming(): 
    client, client_address = server.accept()
    print("%s:%s has connected." % client_address)

    return client, client_address

def handle_client(client_sock, client_addresses):
    msg = client_sock.recv(buffer_size)
    msg = decryptText(msg, privKey)
    print(msg)

pubKey, privKey = load_keys()

host = gethostbyname(gethostname())
port = 42001
<<<<<<< HEAD:ecc/server.py
buffer_size = 160
=======
buffer_size = 2048
>>>>>>> 3c9e07ed1ac5ef0e92e492178c1899c13427a9b8:without_zkp/ecc/server.py
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