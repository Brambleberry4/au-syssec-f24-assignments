#!/usr/bin/env python3

# CBC padding oracle attack
# - lenerd

import requests
import sys

def oracle(iv, block, base_url):
    res = requests.get(f'{base_url}/quote/', cookies={'authtoken': iv.hex() + block.hex()})
    if res.text.startswith("'utf") or res.text.startswith("No"):
        return True
    else:
        return False
    #print(res.text)
    #return res.text.startswith("'utf")

def single_block_attack(block, base_url):
    zeroed_iv = [0] * 16

    for pad_val in range(1, 17):
        padding_iv = [pad_val ^ b for b in zeroed_iv]

        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)
            if oracle(iv, block, base_url):
                print(candidate)
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
        print(zeroed_iv)
    return zeroed_iv

def attack(base_url):
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

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    print(attack(sys.argv[1]).decode())
