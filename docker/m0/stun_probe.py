"""Print our public IP as seen over UDP, via a STUN binding request (RFC 5389)."""
import os
import socket
import struct
import sys

MAGIC = 0x2112A442
host, port = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else ("stun.l.google.com", 19302)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
txid = os.urandom(12)
s.sendto(struct.pack("!HHI", 0x0001, 0, MAGIC) + txid, (host, port))
data, _ = s.recvfrom(2048)

pos = 20
while pos + 4 <= len(data):
    atype, alen = struct.unpack_from("!HH", data, pos)
    val = data[pos + 4: pos + 4 + alen]
    if atype == 0x0020 and val[1] == 0x01:  # XOR-MAPPED-ADDRESS, IPv4
        ip = struct.unpack("!I", val[4:8])[0] ^ MAGIC
        print(socket.inet_ntoa(struct.pack("!I", ip)))
        sys.exit(0)
    pos += 4 + alen + (-alen % 4)
sys.exit("no XOR-MAPPED-ADDRESS in STUN response")
