#!/usr/bin/env python

import argparse
import hashlib
import base64
import os
import sys
import struct
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

class Decryptor():
    def __init__(self, key_file):
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)

        self.logger.info("Reading private key.")
        try:
            with open(key_file,  'r') as f:
                private_key = f.read()
        except:
            self.logger.critical("Could not open private key file. Exiting.")
            sys.exit(1)
        self.private_key = RSA.importKey(private_key)

    def extract_package_key(self, enc_package_file):
        self.logger.info("Extracting private key from package file.")
        with open(enc_package_file,  'rb') as f:
            ciphertext = f.read()
            key_position = ciphertext.rindex('PKGKEY')
            self.enc_package_key = ciphertext[key_position:].split('PKGKEY')[1]
            with open(enc_package_file.replace('.enc', '.tmp'), 'wb') as outfile:
                # create copy of package file and trim package key
                outfile.write(ciphertext)
                outfile.seek(0)
                outfile.truncate(key_position)

    def decrypt_package_key(self):
        self.logger.info("Decrypting package key.")
        return self.private_key.decrypt(self.enc_package_key)

    def decrypt_package(self, key, in_filename, out_filename=None, chunksize=24*1024):
        self.logger.info("Decrypting file.")

        if not out_filename:
            out_filename = os.path.splitext(in_filename)[0]

        with open(in_filename.replace('.enc', '.tmp'), 'r') as infile:
            origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
            iv = infile.read(16)
            decryptor = AES.new(key.decode('hex'), AES.MODE_CBC, iv)

            with open(out_filename.replace('.enc', ''), 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    outfile.write(decryptor.decrypt(chunk))
                outfile.truncate(origsize)
        os.remove(in_filename.replace('.enc', '.tmp'))


def main():

    argument_parser = argparse.ArgumentParser(
        description=u'Script to decrypt collection package of triage artifacts given a private key.')

    argument_parser.add_argument(
        u'-k', u'--key', dest=u'private_key_file', action=u'store', default=False,
        help=u'Private key used to decrypt collection package.')

    argument_parser.add_argument(
        u'-f', u'--package-file', dest=u'package_file', action=u'store', type=str,
        default="/", help=u'Target package file to decrypt.')

    options = argument_parser.parse_args()
    d = Decryptor(options.private_key_file)
    d.extract_package_key(options.package_file)
    d.decrypt_package(d.decrypt_package_key(), options.package_file)

if __name__ == "__main__":
    main()
