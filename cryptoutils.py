from Crypto.Cipher import PKCS1_OAEP as RSACipher, AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHAKE256
from Crypto.Util.number import long_to_bytes

AES_KEY_LEN = 32
AES_ENC_KEY_LEN = 128
AES_TAG_LEN = 16
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

def partition(data, *points):
    ''' Split sequence into len(points) + 1 parts in specified points '''
    parts = []
    cur = 0
    for point in points:
        cur_next = cur + point
        parts.append(data[cur: cur_next])
        cur = cur_next
    parts.append(data[cur:])
    return parts

