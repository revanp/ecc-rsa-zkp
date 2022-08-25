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

    privKey = key.to_hex()
    pubKey = key.public_key.to_hex()
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

start_time = time.time()
pubKey, privKey = load_keys()

host = 'localhost'
# host = gethostbyname(gethostname())
port = 42001
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
    ciphertext = encryptText(msg, pubKey)

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