import pyDes as pydes
import socket
import sys
from random import seed
from random import random

# This is a small chat program between a server and a client
# The messages are encrypted using pyDes, a pure python implmentation of DES
# here is the documentation for pyDes https://github.com/twhiteman/pyDes

# this will be put in a seperate file later
DES_key = None
# for now just localhost
host = "127.0.0.1"
isServer = False
# for now its over 9000
port = 9001


def generateKey():
    # reset key
    f = open("KEY.txt", "w")
    f.close()
    # seed random number generator
    seed(1)
    # 8 bit key
    f = open("KEY.txt", "a")
    for x in range(8):
        # float between 0-1
        temp = random()
        if temp <= 0.5:
            temp = str(0)
        else:
            temp = str(1)
        f.write(temp)
    f.close()


def readKey(fileName):
    f = open(fileName, "r")
    DES_key = str(f.readline().strip('\r\n'))
    print("reading key from file : " + DES_key)


def StartChat():
    # Create a TCP/IP socket
    socket_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # build server address from user input
    server_address = (host, port)

generateKey()
readKey("KEY.txt")


# this is taken from the pyDes documentation page
data = input("Please encrypt my data").strip("\r\n")
# we use the PAD_PKCS5 because this can handle padded and unpadded ciphers.
# so there is no reason not to use this pad mode.
key = pydes.des("DESCRYPT", pydes.CBC, DES_key,
                pad=None, padmode=pydes.PAD_PKCS5)
message = key.encrypt(data)

cipher = key.encrypt(data)
print("Encrypted: %r" % cipher)
print("Decrypted: %r" % key.decrypt(cipher))
