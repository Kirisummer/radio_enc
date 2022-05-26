from Crypto.Cipher import PKCS1_OAEP as RSACipher, AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHAKE256
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes

from functools import cache
from typing import NamedTuple

AES_KEY_LEN = 32
AES_TAG_LENGTH = 16
AES_NONCE_LEN = 16
RSA_HASH_LEN = 16
SHA256_HASH_LEN = 32

def generate_rsa_key(key_length):
    return RSA.generate(key_length)

def rsa_key_from_file(filename):
    with open(filename) as f:
        key = RSA.importKey(f.read())
    return key

def rsa_key_hash(rsa_key):
    hash_obj = SHAKE256.new()
    for integer in (rsa_key.n, rsa_key.e):
        hash_obj.update(long_to_bytes(integer))
    return hash_obj.read(RSA_HASH_LEN)

def get_max_payload_size(rsa_key):
    modulo = len(long_to_bytes(rsa_key.n))
    return modulo - 2 - 2 * SHA256_HASH_LEN

def encrypt(pub_key, data):
    symm_key, enc_key = generate_aes_key(pub_key, AES_KEY_LEN)
    cipher = aes_encode(symm_key, data)
    concat = b''.join((rsa_key_hash(pub_key), enc_key, cipher))
    encoded = err_encode(concat)
    return encoded

def rsa_encode(pub_key, data):
    dataview = memoryview(data)
    max_part_size = get_max_payload_size(pub_key)
    enc_parts = []

    cipher = RSACipher.new(pub_key, hashAlgo=SHA256)
    for start in range(0, len(data), max_part_size):
        part = dataview[start: start + max_part_size]
        enc_parts.append(cipher.encrypt(part))

    return b''.join(enc_parts)

def generate_aes_key(pub_key, length):
    key = get_random_bytes(length)
    return key, rsa_encode(pub_key, key)

def aes_encode(symm_key, data):
    cipher = AES.new(symm_key, AES.MODE_EAX, mac_len=AES_TAG_LENGTH)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return b''.join((nonce, tag, ciphertext))

def err_encode(data):
    return data

