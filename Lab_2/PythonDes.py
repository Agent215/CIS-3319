# Abraham Schultz 9/14/2020
import pyDes as pydes
import socket
import sys
from random import seed
from random import random
import os.path
import hmac
import hashlib
# This is a small chat program between a server and a client
# The messages are encrypted using pyDes, a pure python implmentation of DES
# here is the documentation for pyDes https://github.com/twhiteman/pyDes

CLIENT = "CLIENT"
SERVER = "SERVER"
CONNECTION_BUFFER_SIZE = 1024000000  # 1024 MB for good measure
DES_KEY_FILE = "KEY.txt"
HMAC_KEY_FILE = "HMAC_KEY.txt"
args = []

#return false if incorrect syntax
def parseArgs():
    if len(sys.argv) < 4:
        print("Please Enter: [HostName][PortNumber][Server/Client]")
        return False
    args.append(sys.argv[1])
    args.append(sys.argv[2])
    args.append(sys.argv[3])
    return True


# generate 8 bit long string of random 0's and 1's
def generateKey():
    # reset key
    f = open(DES_KEY_FILE, "w")
    f.close()
    # seed random number generator
    seed()
    # 8 bit key
    f = open(DES_KEY_FILE, "a")
    for x in range(8):
        # float between 0-1
        temp = random()
        if temp <= 0.5:
            temp = str(0)
        else:
            temp = str(1)
        f.write(temp)
    f.close()

# subroutine to read in key
# pass file name to read, and if its a hash, this just is for custom print out
def readKey(fileName, hmac):
    f = open(fileName, "r")
    key = str(f.readline().strip('\r\n'))
    if hmac == True:
        print("reading key from HMAC key file : " + key)
    else:
        print("reading key from DES key file : " + key)
    return key

# this function runs the server or client side script depending on user input
def StartChat(deskey, hmackey):
    # Create a TCP/IP socket
    socket_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # build server address from user input
    server_address = (args[0], int(args[1]))

    # Server side
    if args[2].lower() == SERVER.lower():

        #initialize the hash as empty using the common key from our key file and md5 hashing algo
        digest_maker = hmac.new(hmackey, b'', hashlib.md5,)
        # set up server to listen and bind to appropriate host and port
        socket_.bind(server_address)
        # listen for client on that socket
        socket_.listen()
        print("waiting for client to connect")
        conn, server_address = socket_.accept()
        print("client connected")
        print("DES KEY:" + deskey)

        # run until program closes
        while True:

            # choose the mode and the padding. padmode can accept padding if neccesary
            key = pydes.des("DESCRYPT", pydes.CBC, deskey,
                            pad=None, padmode=pydes.PAD_PKCS5)
            # get user input
            message = input("Enter Text To send, q to quit: ").strip("\r\n")
            # quit command
            if message == "q":
                break
            # hash the message
            digest_maker.update(message.encode('utf-8'))
            digest = digest_maker.hexdigest()
            print("hash of plaintext is :" + digest)
            
            # concat message with has, add delineater

            message = (message + digest).encode('utf-8')

            #Encrypt message with hash
            cipher = key.encrypt(message)
            print("sending ciphertext :" + str(cipher))
            #send encypted message
            conn.send(cipher)
            print("waiting for message from client")
            
            receivedMessage = conn.recv(CONNECTION_BUFFER_SIZE)
            print("received ciphertext:" + str(receivedMessage))
            # decrypt incoming message
            receivedMessage = key.decrypt(
                receivedMessage, padmode=pydes.PAD_PKCS5)
            #split off message 
            receivedMessage, receivedHmac = splitMessage(receivedMessage)
            # new hash for incoming message
            digest_makersen = hmac.new(hmackey, b'', hashlib.md5,)
            digest_makersen.update(receivedMessage)
            digest = digest_makersen.hexdigest()
            calculatedHmac = digest

            print("Decrypted text: "+(receivedMessage).decode('utf-8'))
            print("recieved hmac: " + str(receivedHmac.decode('utf-8')))
            print("calculated hmac: " + calculatedHmac)

            checkHash(calculatedHmac, receivedHmac)
        

            

    # Client side
    elif args[2] == CLIENT.lower():

        #initialize the hash as empty using the common key from our key file and md5 hashing algo
        digest_maker = hmac.new(hmackey, b'', hashlib.md5,)
        socket_.connect(server_address)
        print("DES KEY:" + deskey)
        # run until program closes
        while True:
            # get user input
            print("waiting for message from server")

            receivedMessage = socket_.recv(CONNECTION_BUFFER_SIZE)
            print("received ciphertext:" + str(receivedMessage))

            key = pydes.des("DESCRYPT", pydes.CBC, deskey,
                            pad=None, padmode=pydes.PAD_PKCS5)
            receivedMessage = key.decrypt(
                receivedMessage, padmode=pydes.PAD_PKCS5)
            #split off message 
            receivedMessage, receivedHmac = splitMessage(receivedMessage)
            # hash the received plaintest to calculate hash
            digest_maker.update(receivedMessage)
            digest = digest_maker.hexdigest()
            calculatedHmac = digest

            print("Decrypted text: "+(receivedMessage).decode('utf-8'))
            print("recieved hmac: " + str(receivedHmac.decode('utf-8')))
            print("calculated hmac: " + calculatedHmac)
            
            checkHash(calculatedHmac, receivedHmac)
           
            message = input("Enter Text To send, q to quit: ").strip("\r\n")
            # quit command
            if message == "q":
                break
            #new for differnent message
            digest_maker_rec = hmac.new(hmackey, b'', hashlib.md5,)
            digest_maker_rec.update(message.encode('utf-8'))
            digest = digest_maker_rec.hexdigest()
            print("hash of plaintext is :" + digest)
            message = (message + digest).encode('utf-8')
            cipher = key.encrypt(message)
            print("sending ciphertext:" + str(cipher))
            socket_.send(cipher)
    else:
        print("please enter a either server or client as third argument")


# msg is a byte array 
# split off hash and message
def splitMessage(msg):
    length = len(msg)
    m = msg[:(length - 32)]
    h = msg[(length - 32):]
    return m, h


#function to compare hashs
def checkHash(calc, recv):
    if calc == recv.decode('utf-8'):
        print("HMAC VERIFIED")
    else:
        print("HMAC NOT VERIFIED, THIS MESSAGE INTEGRITY CAN NOT BE CONFIRMED")


def main():
    if parseArgs():
        # read in hmac key
        # we just assume that both sender and reciever have the key
        hmacKey = readKey(HMAC_KEY_FILE, True).encode('utf-8')
        # only generate a new key if one does not already exist
        if (os.path.exists(DES_KEY_FILE)) == False:
            generateKey()
            key = readKey(DES_KEY_FILE, False)
        else:
            key = readKey(DES_KEY_FILE, False)
        if key is not None:
            StartChat(key, hmacKey)


if __name__ == "__main__":
    main()
