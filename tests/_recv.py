#!/usr/bin/env python3
"""Receive one UDP datagram and print its payload as hex. Run on the host.
Usage: _recv.py <bind_ip> <port> [timeout_s]"""
import socket, sys
ip, port = sys.argv[1], int(sys.argv[2])
to = float(sys.argv[3]) if len(sys.argv) > 3 else 4.0
r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
r.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
r.bind((ip, port)); r.settimeout(to)
try:
    data, _ = r.recvfrom(2048)
    print(data.hex())
except socket.timeout:
    print("TIMEOUT")
