#!/usr/bin/env python3

import argparse
import base64
import binascii
import gzip
import sys

from Crypto.Cipher import AES
from Crypto.Util import Counter


# Decrypt sample input with key: '2KuX63Oh+nlRFRLIrxib3g==', iv: 'VaZkOTf+fn2YI1uy/snFGg=='

def main():
    args = command_line_args()
    with open(args.encrypted_file, '+rb') as encrypted_file:
        encrypted = encrypted_file.read()
        decrypted = decrypt(args.data_key, args.iv, encrypted)
        final = gzip.decompress(decrypted) if args.decompress else decrypted
        sys.stdout.buffer.write(final)


def decrypt(key, iv, ciphertext):
    iv_int = int(binascii.hexlify(base64.b64decode(iv)), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(base64.b64decode(key), AES.MODE_CTR, counter=ctr)
    return aes.decrypt(ciphertext)


def command_line_args():
    parser = argparse.ArgumentParser(description='Decrypt files produced by htme.')
    parser.add_argument('-i', '--iv', required=True, help='The initialisation vector used to encrypt.')
    parser.add_argument('-k', '--data-key', required=True, help='The plaintext decryption key.')
    parser.add_argument('-z', '--decompress', action='store_true', help='Decompress the decrypted text.')
    parser.add_argument('encrypted_file', help='The encrypted file.')
    return parser.parse_args()


if __name__ == '__main__':
    main()
