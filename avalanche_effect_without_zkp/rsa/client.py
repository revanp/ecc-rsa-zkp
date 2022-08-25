from socket import *
from threading import Thread
from tracemalloc import start
from noknow.core import ZK, ZKSignature, ZKParameters, ZKData, ZKProof
from getpass import getpass
from queue import Queue
from datetime import datetime
from bitstring import BitArray

import rsa 
import random
import time
import sys

def generate_keys():
    (pubKey, privKey) = rsa.newkeys(3072)
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

start_time = time.time()
pubKey, privKey = load_keys()

host = 'localhost'
# host = gethostbyname(gethostname())
port = 42000
address = (host, port)

count_argv = 1
if len(sys.argv) > 1:
    count_argv = int(sys.argv[1])

loop_count = 0
average_percentage = 0
memory_usage = 0
for i in range(count_argv): 
    client = socket(AF_INET, SOCK_STREAM)
    client.connect(address)

    msg = str(random.randint(0, 1000))
    ciphertext = encrypt(msg, pubKey)
    now = str(datetime.now().timestamp())

    # AVALANCHE
    msg_bin = int.from_bytes(msg.encode('ascii'), byteorder = sys.byteorder)
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
    # print ("Avalanche effect \t:\t", AE, "%")

    average_percentage += AE
    # END AVALANCHE

    # MEMORY
    memory_usage += sys.getsizeof(ciphertext)
    # END MEMORY

    loop_count = i + 1
    client.send(bytes(ciphertext))

end_time = time.time()

print("\n----------------------------------------------")
print(loop_count, " packages sent")
print("Average of Avalanche Effect : ", (average_percentage / loop_count), "%")
print("Used memory : ", (memory_usage / 1000), "Kb")
print("Execution time : ", (end_time - start_time), " seconds")