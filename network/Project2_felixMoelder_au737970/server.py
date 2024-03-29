import socket
import struct
from Crypto.Cipher import AES
from secret_server import cryptographic_key

def decrypt(ciphertext):
    # remove padding and decrypt with given algorithm and key
    def _unpad(s):
        return s[:-s[-1]]
    iv = bytes([0x00] * 16)
    cipher = AES.new(cryptographic_key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext)
    return _unpad(plaintext)

if __name__ == '__main__':
    print('****Server started****')
    print('Listen:...')
    # Create ICMP socket
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
    s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    while 1:
        # receive packets and addresses from socket
        recPacket, addr = s.recvfrom(1024)
        # isolate icmp header and icmp payload
        icmp_header = recPacket[20:28]
        icmp_payload = recPacket[28:]
        # extract type and other header parts
        type, code, checksum, p_id, sequence = struct.unpack('!BBHHH', icmp_header)
        # filter only ICMP packets with type 47
        if type == 47:
            # Decrypt and print source address and message
            plain = decrypt(icmp_payload)
            print('Received from (' + addr[0] + '): ' + plain.decode())
