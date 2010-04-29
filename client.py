#!/usr/bin/python

# simple implementation of rcf client
import socket
import struct 


host="172.20.0.2"
port=8888
sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect((host,port))
data=struct.pack("!HHH16s16s64s",1,22,80,"command","add","http")
sock.send(data)
