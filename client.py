#!/usr/bin/env python3
import socket
import ssl

# SET VARIABLES
msg = "Hello, wordl!"
HOST, PORT = '127.0.0.1', 6666

# CREATE SOCKET
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)

# WRAP SOCKET
wrappedSocket = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLS, keyfile="pub-key.pem")

# CONNECT AND PRINT REPLY
wrappedSocket.connect((HOST, PORT))
wrappedSocket.send(msg)
print(wrappedSocket.recv(1024))

# CLOSE SOCKET CONNECTION
wrappedSocket.close()