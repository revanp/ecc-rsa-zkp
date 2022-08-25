from socket import *
from threading import Thread
from datetime import datetime
from noknow.core import ZK, ZKSignature, ZKParameters, ZKData, ZKProof

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

    server_password = "brigithacantik"
    server_zk = ZK.new(curve_name="secp384r1", hash_alg="sha3_512")
    server_signature: ZKSignature = server_zk.create_signature(server_password)

    client_signature = ZKSignature.load(msg)
    client_zk = ZK(client_signature.params)

    token = server_zk.sign(server_password, client_zk.token())
    client_sock.send(bytes(token.dump(separator=":"), 'utf-8'))

    proof = client_sock.recv(buffer_size).decode('utf-8')
    proof = ZKData.load(proof)
    token = ZKData.load(proof.data, ":")

    if server_zk.verify(token, server_signature) == True:
        if client_zk.verify(proof, client_signature, data=token) == True :        
            response = b'Berhasil'
        else:
            response = b'Gagal'        
    else:
        response = b'Gagal'

    client_sock.send(bytes(response))

pubKey, privKey = load_keys()

host = 'localhost'
# host = gethostbyname(gethostname())
port = 42000
buffer_size = 2048
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
