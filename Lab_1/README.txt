PYTHONDES.py
************

PythonDes.py is a simple chat program using a single threaded client server.

The messages are encrypted using pyDes python module, a pure python implementation of DES
here is the documentation for pyDes https://github.com/twhiteman/pyDes

This was developed using visual studio code and python 3.8.3
***********************************************************************************************************
Instructions to run:

- Within you CLI navigate to the directory containing PythonDes.py
- The script takes three arguments to run
	1. [hostname]
	2. [port number]
	3. [server/client]

EXAMPLE OF HOW TO USE (type the below code in to your CLI):
python PythonDes.py 127.0.0.1 6001 server

- If this ran correctly you should get output that looks like this:

reading key from file : 11100110  // your key will be different
waiting for client to connect
client connected

- while the server is running you must open another terminal and run the client with the same host and port info:
EXAMPLE OF CLIENT:
python PythonDes.py 127.0.0.1 6001 client

- If client successfully established connection with server the following will print:
6001 client
reading key from file : 11100110
DES KEY:11100110
waiting for message from server

Then in the server terminal type something to send. 
You should see the ciphertext and the decrypted plaintext on the client side.
You will then be prompted to send a message to the server.

Thats it your done!
type q to quit when you are finished.

 
