from ciphers import Rsa, partition

def encrypt(key_cipher, key, key_hasher, ciphers, text):
    payload = [key_hasher(key)]
    ciphertext = text
    for cipher in ciphers:
        session_key = cipher.generate_key()
        enc_key = key_cipher.encrypt(key, session_key)
        ciphertext = cipher.encrypt(session_key, ciphertext)
        payload.append(enc_key)
    payload.append(ciphertext)
    return b''.join(payload)

def decrypt(key_cipher, key, key_hasher, ciphers, ciphertext):
    actual_hash = key_hasher(key)
    key_lens = [key_cipher.encrypted_len(cipher.key_len) for cipher in ciphers]
    key_hash, *keys, ciphertext = partition(
            ciphertext,
            len(actual_hash),
            *key_lens)
    for cipher, enc_key in reversed(tuple(zip(ciphers, keys))):
        session_key = key_cipher.decrypt(key, enc_key)
        ciphertext = cipher.decrypt(session_key, ciphertext)
    return ciphertext

