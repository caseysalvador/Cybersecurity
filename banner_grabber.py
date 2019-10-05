#!/usr/bin/python3

import socket

s = socket.socket()

ip = input("Please enter the IP: ")
port = input("Please enter the port: ")

s.connect((ip, port))

print(s.recv(1024))
