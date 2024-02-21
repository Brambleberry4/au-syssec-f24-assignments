#!/usr/bin/env python3

# CBC padding oracle attack
# - lenerd

import requests
import sys

def single_block_attack(block, base_url):
    zeroed_iv = [0] * 16

    padding_iv = [1 ^ b for b in zeroed_iv]

    print(padding_iv)
    print(block)

    for cand in range(256):
        padding_iv[-1] = cand
        iv = bytes(padding_iv)
        res = requests.get(f'{base_url}/quote/', cookies={'authtoken': iv.hex() + block.hex()})
        print(cand, res.text)

    print(iv)

    for pad_val in range(1, 17):
        padding_iv = [pad_val ^ b for b in zeroed_iv]

        for cand in range(256):
            padding_iv[-pad_val] = cand
            iv = bytes(padding_iv)
            res = requests.get(f'{base_url}/quote/', cookies={'authtoken': iv.hex() + block.hex()})
            if res.text != 'Padding is incorrect.':
                print('nop')

        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)
            res = requests.get(f'{base_url}/quote/', cookies={'authtoken': block.hex()})
            if oracle(iv, block):
                if pad_val == 1:
                    # make sure the padding really is of length 1 by changing
                    # the penultimate block and querying the oracle again
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not oracle(iv, block):
                        continue  # false positive; keep searching
                break
        else:
            raise Exception("no valid padding byte found (is the oracle working correctly?)")

        zeroed_iv[-pad_val] = candidate ^ pad_val

    return zeroed_iv

def attack(base_url):
    # get cookie from server
    authtoken = requests.get(f'{base_url}').cookies['authtoken']
    # extract cookie and seperate into iv and 16 byte cipherblocks
    token = bytes.fromhex(authtoken)
    iv = token[:16]
    ciphertext = token[16:]
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    result = b''
    # iterate through the blocks
    for x in blocks:
        # call the attack for a single block
        dec = single_block_attack(x, base_url)
        # Xor with ciphertext of last round and update result and IV
        pt = bytes(iv_byte ^ dec_byte for iv_byte,dec_byte in zip(iv,dec))
        result += pt
        iv = x
    return result

def test_systems_security(base_url):
    new_ciphertext = bytes.fromhex('2cc9a9fc7cb4dc60f1df7babc4bf82c1122b12cbd8a1c10e1d7f1d4cf57c60ed8cb3703e30ff4b1a2a9af418df999c71b331721a24e713668d0478351a4ccad77fa6abff498d919b3773e6e25fcad5556545a6339b9d4f42c854f96e940a538342424242424242424242424242424242')
    for x in range(256):
        print(hex(x))
        first_ciph = '2cc9a9fc7cb4dc60f1df7babc4bf82'
        sec_ciph = '122b12cbd8a1c10e1d7f1d4cf57c60ed'
        comb = first_ciph + hex(x) + sec_ciph
        fin = bytes.fromhex(comb)
    
    oracleciphertext = bytes.fromhex('2cc9a9fc7cb4dc60f1df7babc4bf82' + var + '122b12cbd8a1c10e1d7f1d4cf57c60ed')
    res = requests.get(f'{base_url}/quote/', cookies={'authtoken': oracleciphertext.hex()})
    print(f'[+] done:\n{res.text}')

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    attack(sys.argv[1])
    #test_systems_security(sys.argv[1])
