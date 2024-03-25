# Imitates a server that only listens for ICMP packages. 

import socket
import struct

encryption_key = b'\xdak5\xe8\x06\xd1\x9ctchX\xd9\x93\xa2\xa8C'

s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
while 1:
    recPacket, addr = s.recvfrom(1024)
    icmp_header = recPacket[20:28]
    icmp_payload = recPacket[36:]
    #print(recPacket)
    #print(icmp_header)
    #print(icmp_payload.decode())
    print(len(icmp_payload))
    type, code, checksum, p_id, sequence = struct.unpack('!BBHHH', icmp_header)
    if type == 47:
        print("type: [" + str(type) + "] code: [" + str(code) + "] checksum: [" + str(checksum) + "] p_id: [" + str(p_id) + "] sequence: [" + str(sequence) + "]")