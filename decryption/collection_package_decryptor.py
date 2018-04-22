#!/usr/bin/env python
"""
macOS triage is a python script to collect various macOS logs, artifacts, and other data.

Copyright (c) 2018 nrvana

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

__author__ = "nrvana"
__credits__ = ["Brian Marks", "Dan O'Day"]
__license__ = "MIT"
__version__ = "0.2"


import argparse
import logging
import os
import struct
import sys

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA


class Decryptor():
    def __init__(self, key_file, enc_package_file):
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)
        self.enc_package_file = enc_package_file

        if self._valid_package_file():
            self.logger.info("Reading private key.")
            try:
                with open(key_file,  'r') as f:
                    private_key = f.read()
            except:
                self.logger.critical("Could not open private key file. Exiting.")
                sys.exit(1)
            self._private_key = RSA.importKey(private_key)
            self._enc_package_key = None
            self._extract_package_key()
            self._decrypted_package_key = self._decrypt_package_key()
        else:
            sys.exit(1)

    def _valid_package_file(self):
        ext = os.path.splitext(self.enc_package_file)[1]
        if ext and ext is not None and ext == '.enc':
            self.logger.info("Package has expected *.enc file extension.")
            return True
        else:
            self.logger.critical("Unrecognized package file name format (missing *.enc extension).")
            return False

    @staticmethod
    def _replace_extension(filename, new_extension):
        return ''.join([os.path.splitext(filename)[0], new_extension])

    def _extract_package_key(self):
        self.logger.info("Extracting private key from package file.")
        with open(self.enc_package_file,  'rb') as f:
            ciphertext = f.read()
            key_position = ciphertext.rindex('PKGKEY')
            self._enc_package_key = ciphertext[key_position:].split('PKGKEY')[1]
            with open(self._replace_extension(self.enc_package_file, '.tmp'), 'wb') as outfile:
                # create copy of package file and trim package key
                outfile.write(ciphertext)
                outfile.seek(0)
                outfile.truncate(key_position)

    def _decrypt_package_key(self):
        self.logger.info("Decrypting package key.")
        if self._enc_package_key and self._enc_package_key is not None:
            return self._private_key.decrypt(self._enc_package_key)
        else:
            self.logger.error("Private key was not successfully extracted from package file.")
            return None

    def decrypt_package(self, out_filename=None, chunksize=24*1024):
        if self._decrypted_package_key and self._decrypted_package_key is not None:
            self.logger.info("Decrypting file.")

            if not out_filename:
                out_filename = os.path.splitext(self.enc_package_file)[0]

            with open(self._replace_extension(self.enc_package_file, '.tmp'), 'r') as infile:
                origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
                iv = infile.read(16)
                decryptor = AES.new(self._decrypted_package_key.decode('hex'), AES.MODE_CBC, iv)

                with open(self._replace_extension(out_filename, ''), 'wb') as outfile:
                    while True:
                        chunk = infile.read(chunksize)
                        if len(chunk) == 0:
                            break
                        outfile.write(decryptor.decrypt(chunk))
                    outfile.truncate(origsize)
            os.remove(self._replace_extension(self.enc_package_file, '.tmp'))
        else:
            self.logger.critical("Unable to decrypt package key.")


def main():
    # add/parse args
    argument_parser = argparse.ArgumentParser(
        description=u'Script to decrypt collection package of triage artifacts given a private key.')

    argument_parser.add_argument(
        u'-k', u'--key', dest=u'private_key_file', action=u'store', default=False,
        help=u'Private key used to decrypt collection package.')

    argument_parser.add_argument(
        u'-f', u'--package-file', dest=u'package_file', action=u'store', type=str,
        default="/", help=u'Target package file to decrypt.')

    options = argument_parser.parse_args()

    # decrypt package
    d = Decryptor(options.private_key_file, options.package_file)
    d.decrypt_package()


if __name__ == "__main__":
    main()
