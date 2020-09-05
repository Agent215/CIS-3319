import pyDes
import socket
import sys

#This is a small chat program between a server and a client
#The messages are encrypted using pyDes, a pure python implmentation of DES
# here is the documentation for pyDes https://github.com/twhiteman/pyDes

# this will be put in a seperate file later
DES_key = "\0\0\0\0\0\0\0\0"

# for now just localhost
host = "127.0.0.1"

#for now its over 9000
port = 9001

socket_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (host, port)


# this is taken from the pyDes documentation page
data = "Please encrypt my data"
# we use the PAD_PKCS5 because this can handle padded and unpadded ciphers. 
# so there is no reason not to use this pad mode. 
key = pyDes.des("DESCRYPT", pyDes.CBC, DES_key, pad=None, padmode=pyDes.PAD_PKCS5)
cipher = key.encrypt(data)
print ("Encrypted: %r" % cipher) 
print ("Decrypted: %r" % key.decrypt(cipher))
assert key.decrypt(cipher) == data

