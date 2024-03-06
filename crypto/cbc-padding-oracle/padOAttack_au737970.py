#!/usr/bin/env python3

# CBC padding oracle attack
# - lenerd

import requests
import sys
import secrets
from Crypto.Util.Padding import pad, unpad

def oracle(iv, block, base_url):
    res = requests.get(f'{base_url}/quote/', cookies={'authtoken': iv.hex() + block.hex()})
    return res.text.startswith("'utf") or res.text.startswith("No")

def single_block_attack(block, base_url):
    zeroed_iv = [0] * 16

    for pad_val in range(1, 17):
        padding_iv = [pad_val ^ b for b in zeroed_iv]

        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)
            if oracle(iv, block, base_url):
                if pad_val == 1:
                    # make sure the padding really is of length 1 by changing
                    # the penultimate block and querying the oracle again
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not oracle(iv, block, base_url):
                        continue  # false positive; keep searching
                break
        else:
            raise Exception("no valid padding byte found (is the oracle working correctly?)")
        zeroed_iv[-pad_val] = candidate ^ pad_val
    return zeroed_iv

def decAttack(base_url):
    # get cookie from server
    authtoken = requests.get(f'{base_url}').cookies['authtoken']
    # extract cookie and seperate into iv and 16 byte cipherblocks
    token = bytes.fromhex(authtoken)
    blocks = [token[i:i+16] for i in range(0, len(token), 16)]
    result = b''
    iv = blocks[0]
    # iterate through the blocks
    for x in blocks[1:]:
        # call the attack for a single block
        dec = single_block_attack(x, base_url)
        # Xor with ciphertext of last round and update result and IV
        pt = bytes(iv_byte ^ dec_byte for iv_byte,dec_byte in zip(iv,dec))
        result += pt
        iv = x
    return result

def single_block_rec(cBlock, pBlock, base_url):
    cX = single_block_attack(cBlock, base_url)
    return pBlock ^ cX 

def encAttack(base_url):
    newPlaintext = f'I should have used authenticated encryption because ... plain CBC is not secure!'.encode()
    print(newPlaintext)
    print(len(newPlaintext), type(newPlaintext))
    plainBlocks = [newPlaintext[i:i+16] for i in range(0, len(newPlaintext), 16)]
    print(len(plainBlocks), len(plainBlocks[0]))
    for x in plainBlocks:
        dec = single_block_attack()
    c4 = secrets.token_bytes(16)
    decC4 = single_block_rec(c4, base_url)
    print(decC4).decode()
    return single_block_attack(c4, base_url)

    
    

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    print(encAttack(sys.argv[1]))
    #print(type(encAttack(sys.argv[1])).decode())
    #print(type(decAttack(sys.argv[1])))
    #print(decAttack(sys.argv[1]).decode())
