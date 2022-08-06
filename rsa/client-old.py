import rsa
import random
import socket
import threading
import hashlib
import itertools
import sys
import time

done = False
def animate():
    for c in itertools.cycle(['....','.......','..........','............']):
        if done:
            break
        sys.stdout.write('\rCONFIRMING CONNECTION TO SERVER '+c)
        sys.stdout.flush()
        time.sleep(0.1)

# SOCKET
server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

#host and port input user
host = input("Server Address To Be Connected -> ")
port = int(input("Port of The Server -> "))

#binding the address and port
server.connect((host, port))

# printing "Server Started Message"
thread_load = threading.Thread(target=animate)
thread_load.start()