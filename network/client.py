import sys
import socket
import os
import struct
from Crypto.Cipher import AES
from secret_client import cryptographic_key

BLOCK_SIZE = 16

def calculate_checksum(source_string):
    """
    function given by https://github.com/00dhkim/icmp-tunneling-tool/blob/master/pyping/core.py to calculate the checksum of a given packet
    """
    countTo = (int(len(source_string) / 2)) * 2
    sum = 0
    count = 0

    # Handle bytes in pairs (decoding as short ints)
    loByte = 0
    hiByte = 0
    while count < countTo:
        if (sys.byteorder == "little"):
            loByte = source_string[count]
            hiByte = source_string[count + 1]
        else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
        # sum = sum + (ord(hiByte) * 256 + ord(loByte))
        sum = sum + (hiByte * 256 + loByte)
        count += 2

    # Handle last byte if applicable (odd-number of bytes)
    # Endianness should be irrelevant in this case
    if countTo < len(source_string): # Check for odd length
        loByte = source_string[len(source_string) - 1]
        sum += loByte

    sum &= 0xffffffff # Truncate sum to 32 bits (a variance from ping.c, which
                      # uses signed ints, but overflow is unlikely in ping)

    sum = (sum >> 16) + (sum & 0xffff)    # Add high 16 bits to low 16 bits
    sum += (sum >> 16)                    # Add carry from above (if any)
    answer = ~sum & 0xffff                # Invert and truncate to 16 bits
    answer = socket.htons(answer)

    return answer

def chunkAndEncrypt(msg):
    # function to pad the message and encrypt with given Algorithm and key
    def _pad(s: bytes):
        return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE).encode('utf-8')
    msg = _pad(msg)
    iv = bytes([0x00] * 16)
    cipher = AES.new(cryptographic_key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(msg)
    
if __name__ == '__main__':
    if len(sys.argv) != 2:
        # first argument needs to be an IP address
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)

    while 1:
        print('****Secret channel activated****')
        inp = input('Enter information to send: ')
        # encrypt input
        ciphertext = chunkAndEncrypt(bytes(inp, 'utf-8'))
        # compute checksum for given ciphertext
        checksum = 0
        # get the id of the current process
        id = os.getpid() & 0xFFFF
        dummy_header = struct.pack(
            "!BBHHH", 47, 0, checksum, id, 0
        )
        check = calculate_checksum(dummy_header + ciphertext)
        header = struct.pack(
            "!BBHHH", 47, 0, check, id, 0
        )
        # create packet
        packet = header + ciphertext
        # create socket and send packet to IP address
        icmp = socket.getprotobyname("icmp")
        mysocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        mysocket.sendto(packet, (sys.argv[1], 1))
