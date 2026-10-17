#!/usr/bin/env python3
"""Send one UDP datagram with a given payload to a host:port. Run inside a netns.
Usage: _send.py <dst_ip> <dst_port> <payload_hex> [src_ip]"""
import socket, sys
dst_ip, dst_port, payload_hex = sys.argv[1], int(sys.argv[2]), sys.argv[3]
src_ip = sys.argv[4] if len(sys.argv) > 4 else None
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
if src_ip: s.bind((src_ip, 0))
s.sendto(bytes.fromhex(payload_hex), (dst_ip, dst_port))
print("sent", len(payload_hex)//2, "bytes to", dst_ip, dst_port)
