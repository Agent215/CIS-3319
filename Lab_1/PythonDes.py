# Abraham Schultz 9/14/2020
import pyDes as pydes
import socket
import sys
from random import seed
from random import random
import os.path
# This is a small chat program between a server and a client
# The messages are encrypted using pyDes, a pure python implmentation of DES
# here is the documentation for pyDes https://github.com/twhiteman/pyDes

CLIENT = "CLIENT"
SERVER = "SERVER"
CONNECTION_BUFFER_SIZE = 1024000000  # 1024 MB for good measure
KEY_FILE = "KEY.txt"
args = []


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
    f = open(KEY_FILE, "w")
    f.close()
    # seed random number generator
    seed()
    # 8 bit key
    f = open(KEY_FILE, "a")
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


def readKey(fileName):
    f = open(fileName, "r")
    key = str(f.readline().strip('\r\n'))
    print("reading key from file : " + key)
    return key


# this function runs the server or client side script depending on user input
def StartChat(deskey):
    # Create a TCP/IP socket
    socket_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # build server address from user input
    server_address = (args[0], int(args[1]))

    # Server side
    if args[2].lower() == SERVER.lower():
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
            # get user input
            message = input("Enter Text To send, q to quit: ").strip("\r\n")
            # quit command
            if message == "q":
                break
            # choose the mode and the padding. padmode can accept padding if neccesary
            key = pydes.des("DESCRYPT", pydes.CBC, deskey,
                            pad=None, padmode=pydes.PAD_PKCS5)
            cipher = key.encrypt(message)
            
            print("sending ciphertext :" + str(cipher))
            conn.send(cipher)
            print("waiting for message from client")
            receivedMessage = conn.recv(CONNECTION_BUFFER_SIZE)
            print("received ciphertext:" + str(receivedMessage))
            # decrypt incoming message
            receivedMessage = key.decrypt(
                receivedMessage, padmode=pydes.PAD_PKCS5)
            print("Decrypted text:" + receivedMessage.decode("utf-8"))

    # Client side
    elif args[2] == CLIENT.lower():
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

            print("Decrypted text: "+(receivedMessage).decode("utf-8"))
            message = input("Enter Text To send, q to quit: ").strip("\r\n")
            # quit command
            if message == "q":
                break
            cipher = key.encrypt(message)
            print("sending ciphertext:" + str(cipher))
            socket_.send(cipher)
    else:
        print("please enter a either server or client as third argument")


def main():
    if parseArgs():
        # only generate a new key if one does not already exist
        if (os.path.exists(KEY_FILE)) == False:
            generateKey()
            key = readKey(KEY_FILE)
        else:
            key = readKey(KEY_FILE)
        if key is not None:
            StartChat(key)


if __name__ == "__main__":
    main()
