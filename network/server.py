import socket
import struct
from Crypto.Cipher import AES
from secret_server import cryptographic_key

def decrypt(ciphertext):
    def _unpad(s):
        return s[:-s[-1]]
    
    iv = bytes([0x00] * 16)
    cipher = AES.new(cryptographic_key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext)
    return _unpad(plaintext)


if __name__ == '__main__':
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
    s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    print('****Server started****')
    print('Listen:...')
    while 1:
        recPacket, addr = s.recvfrom(1024)
        sourceIP = socket.inet_ntoa(recPacket[12:16])
        icmp_header = recPacket[20:28]
        icmp_payload = recPacket[28:]
        type, code, checksum, p_id, sequence = struct.unpack('!BBHHH', icmp_header)
        if type == 47:
            plain = decrypt(icmp_payload)
            print('Received from (' + sourceIP + '): ' + plain.decode())
