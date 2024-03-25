# 1. argument: ip address of destination host
import sys
import socket
import os
import struct
from Crypto.Cipher import AES

encryption_key = b'\xdak5\xe8\x06\xd1\x9ctchX\xd9\x93\xa2\xa8C'

BLOCK_SIZE = 16

# put in payload of ICMP package with header type 47
# send

def sending(x):
    
    return

def calculate_checksum(source_string):
    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
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


def headerForPayload(ciphertext):
    checksum = 0
    own_id = os.getpid() & 0xFFFF
    seq_number = 0
    header = struct.pack(
            "!BBHHH", 47, 0, checksum, own_id, seq_number
        )
    return header, own_id

def chunkAndEncrypt(msg):
    # seperate message in 16 byte blocks
    def _pad(s: bytes):
        return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE).encode('utf-8')
    msg = _pad(msg)
    
    iv = bytes([0x00] * 16)
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(msg)
    return ciphertext

def decrypt(ciphertext):
    def _unpad(s):
        return s[:-s[-1]]
    
    iv = bytes([0x00] * 16)
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext)
    return _unpad(plaintext)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    print('****Secret channel activated****')
    inp = input('Enter information to send: ')
    cip = chunkAndEncrypt(bytes(inp, 'utf-8'))
    print(cip)
    checksum = 0
    id = os.getpid() & 0xFFFF
    header = struct.pack(
        "!BBHHH", 47, 0, checksum, id, 0
    )
    check = calculate_checksum(header + cip)

    propHeader = struct.pack(
        "!BBHHH", 47, 0, check, id, 0
    )
    packet = propHeader + cip
    icmp = socket.getprotobyname("icmp")
    mysocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    mysocket.sendto(packet, (sys.argv[1], 1))

    
    #headerStump, id = headerForPayload(cip)
    #print(headerStump)
    #headAndData = headerStump + cip
    #check = calculate_checksum(headAndData)
    #icmp = socket.getprotobyname("icmp")
    #mysocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    #header = struct.pack(
    #    "BBHHH", 47, 0, socket.htons(check), id, 1
    #)
    #packet = header + cip
    #mysocket.sendto(packet, (sys.argv[1],1))    