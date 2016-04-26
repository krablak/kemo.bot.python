#!/usr/bin/env python

import urllib2
import base64
import binascii
import hashlib

from Crypto import Random
from Crypto.Cipher import AES


# ------------------------------
# DEFINE Encryption Class
class Cryptor(object):
    '''
    Provide encryption and decryption function that works with crypto-js.
    https://code.google.com/p/crypto-js/

    Padding implemented as per RFC 2315: PKCS#7 page 21
    http://www.ietf.org/rfc/rfc2315.txt

    The key to make pycrypto work with crypto-js are:
    1. Use MODE_CFB.  For some reason, crypto-js decrypted result from MODE_CBC
       gets truncated
    2. Use Pkcs7 padding as per RFC 2315, the default padding used by CryptoJS
    3. On the JS side, make sure to wrap ciphertext with CryptoJS.lib.CipherParams.create()
    '''

    # AES-256 key (32 bytes) in hexa! modafuka
    KEY = "01ab38d5e05c92aa098921d9d4626107133c7e2ab0e4849558921ebcc242bcb0"
    BLOCK_SIZE = 16

    @classmethod
    def _pad_string(cls, in_string):
        '''Pad an input string according to PKCS#7'''
        in_len = len(in_string)
        pad_size = cls.BLOCK_SIZE - (in_len % cls.BLOCK_SIZE)
        return in_string.ljust(in_len + pad_size, chr(pad_size))

    @classmethod
    def _unpad_string(cls, in_string):
        '''Remove the PKCS#7 padding from a text string'''
        in_len = len(in_string)
        pad_size = ord(in_string[-1])
        if pad_size > cls.BLOCK_SIZE:
            raise ValueError('Input is not padded or padding is corrupt')
        return in_string[:in_len - pad_size]

    @classmethod
    def generate_iv(cls, size=16):
        return Random.get_random_bytes(size)

    @classmethod
    def encrypt(cls, in_string, in_key, in_iv=None):
        '''
        Return encrypted string.
        @in_string: Simple str to be encrypted
        @key: hexified key
        @iv: hexified iv
        '''
        key = binascii.a2b_hex(in_key)

        if in_iv is None:
            iv = cls.generate_iv()
            in_iv = binascii.b2a_hex(iv)
        else:
            iv = binascii.a2b_hex(in_iv)

        aes = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        return in_iv, aes.encrypt(cls._pad_string(in_string))

    @classmethod
    def decrypt(cls, in_encrypted, in_key, in_iv):
        '''
        Return encrypted string.
        @in_encrypted: Base64 encoded
        @key: hexified key
        @iv: hexified iv
        '''
        key = binascii.a2b_hex(in_key)
        iv = binascii.a2b_hex(in_iv)
        aes = AES.new(key, AES.MODE_CFB, iv, segment_size=128)

        decrypted = aes.decrypt(in_encrypted)
        return cls._unpad_string(decrypted)


def encrypt(key, message):
    """
    Encrypts given message using given key.
    :param key: key as string used for encryption.
    :param message: message to encrypted.
    :return: encrypted message as base64 string.
    """
    iv, encrypted = Cryptor.encrypt(message, hashlib.sha256(key).hexdigest())
    iv_bytes = binascii.unhexlify(iv)
    enc_msg_bytes = iv_bytes + encrypted
    cyphertext = binascii.b2a_base64(enc_msg_bytes).rstrip()
    return cyphertext


def decrypt(key, encrypted_message):
    """
    Decrypts given message using given key.
    :param key: key as string used for decryption.
    :param encrypted_message: encrypted message as base64 string.
    :return: decrypted message content.
    """
    # Decode bytes from given base64 message string
    encBytes = binascii.a2b_base64(encrypted_message)
    # First 16 bytes are IV
    iv = binascii.hexlify(encBytes[:16])
    # Rest of bytes represents message content
    cyphertext = encBytes[16:]
    # Perform decryption
    decrypted = Cryptor.decrypt(cyphertext, hashlib.sha256(key).hexdigest(), iv)
    return decrypted


def salt_encryption_key(key):
    """
    Adds default salt to given key.
    :param key: key to be salted.
    :return: salted key.
    """
    return "clientenc" + key + "salt"

def key_to_address(key):
    """
    return equivalent to return encodeURIComponent(sjcl.codec.base64.fromBits(sjcl.hash.sha256.hash("littlebitof" + key + "salt")));

    JS on key "ahoj":    "PzsI7KYsIddiVubh0Li%2FmfTvvjdvZDNbcvQWOo%2FFDbo%3D"
    this code on "ahoj": 'PzsI7KYsIddiVubh0Li%2FmfTvvjdvZDNbcvQWOo%2FFDbo%3D'

    this will be later converted to tests...
    on "ahoj valdimire mrdej maxovi rit":
    "1qHaow4rhi9ZsYUaG3Owo6EzVJR1TnrXzfaGCo96PnE%3D"
    '1qHaow4rhi9ZsYUaG3Owo6EzVJR1TnrXzfaGCo96PnE%3D'

    JS: encodeURIComponent escapes all characters except the following: alphabetic, decimal digits, - _ . ! ~ * ' ( )
    """
    return urllib2.quote(base64.b64encode(hashlib.sha256("littlebitof" + key + "salt").digest()), safe="%-_.~!*'()")

