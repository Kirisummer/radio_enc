from Crypto.Random import get_random_bytes
from collections import deque
from time import perf_counter_ns

def timer(preaction, action, postaction, times):
    records = []
    for i in range(times):
        preaction()
        start = perf_counter_ns()
        action()
        records.append(perf_counter_ns() - start)
        postaction()
    return sum(records) // len(records)

def test_time(cipher, data, times):
    keys = deque()
    encrypted_queue = deque()

    def gen_key():
        key = cipher.generate_key()
        keys.append(key)

    def remove_key():
        keys.popleft()

    def encrypt():
        encrypted = cipher.encrypt(keys[-1], data)
        encrypted_queue.append(encrypted)
        return encrypted

    def decrypt():
        encrypted = encrypted_queue.popleft()
        return cipher.decrypt(keys[0], encrypted)

    def nop():
        pass

    # Run actions for JIT to compile the actions
    for i in range(50):
        gen_key()
        encrypt()
        decrypt()
        remove_key()

    enc_time = timer(gen_key, encrypt, nop, times)
    dec_time = timer(nop, decrypt, remove_key, times)
    return enc_time, dec_time

from ciphers import Aes, Salsa20, ChaCha20
from ciphers import SHA224, SHA256, SHA512, SHA512_224, SHA512_256
import sys

data_size = int(sys.argv[1])
times = int(sys.argv[2])
data = get_random_bytes(data_size)

hashes = (None, SHA224, SHA256, SHA512, SHA512_224, SHA512_256)

def cipher_name(cipher, key_len, hash_algo):
    parts = [cipher.__name__, f'{key_len.value[0]}/{key_len.value[1]}']
    if hash_algo:
        parts.append(hash_algo.name)
    return '-'.join(parts)

ciphers = {
        cipher_name(cipher, key_len, hash_algo): cipher(key_len, hash_algo)
        for cipher in (Salsa20, ChaCha20)
        for key_len in cipher.KeyLen
        for hash_algo in hashes
}
ciphers.update({
        'AES128': Aes(Aes.KeyLen.AES_128),
        'AES192': Aes(Aes.KeyLen.AES_192),
        'AES256': Aes(Aes.KeyLen.AES_256),
})

results = ((name, test_time(cipher, data, times)) for name, cipher in ciphers.items())

for name, (enc, dec) in results:
    print(name, enc, dec, sep='\t')

