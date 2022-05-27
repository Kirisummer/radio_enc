from cryptoutils import *
from math import ceil

def decrypt(priv_key, data):
    decoded = memoryview(err_decode(data))
    rsa_hash, enc_symm_key, ciphertext = \
                                partition(decoded, RSA_HASH_LEN, AES_ENC_KEY_LEN)
    if rsa_hash != rsa_key_hash(priv_key):
        return
    symm_key = rsa_decrypt(priv_key, enc_symm_key)
    data = aes_decode(symm_key, ciphertext)
    return data

def rsa_decrypt(priv_key, ciphertext):
    cipher = RSACipher.new(priv_key, hashAlgo=SHA256)
    text = []
    parts = ceil(len(ciphertext) / AES_ENC_KEY_LEN)
    splits = [AES_ENC_KEY_LEN] * parts
    for enc_part in partition(ciphertext, *splits):
        if enc_part:
            part = cipher.decrypt(enc_part)
            text.append(part)
    return b''.join(text)

def aes_decode(symm_key, ciphertext):
    nonce, tag, ciphertext = partition(ciphertext, AES_NONCE_LEN, AES_TAG_LEN)
    cipher = AES.new(symm_key, AES.MODE_EAX, nonce=nonce)
    text = cipher.decrypt(ciphertext)
    cipher.verify(tag)
    return text

def err_decode(data):
    return data


