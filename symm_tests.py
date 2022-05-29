from Crypto.Random import get_random_bytes
from collections import deque
from time import perf_counter_ns

def timer(label, preaction, action, postaction, times):
    records = []
    for i in range(times):
        preaction()
        start = perf_counter_ns()
        action()
        records.append(perf_counter_ns() - start)
        postaction()
    avg = sum(records) // len(records)
    print(f'{label} over {times} time(s):\t{avg} ns')

def test_symmetric(name, cipher, data, times):
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

    # Run actions first for JIT to compile the actions
    gen_key()
    encrypt()
    decrypt()
    remove_key()

    timer(f'Encyption ({name})', gen_key, encrypt, nop, times)
    timer(f'Decryption ({name})', nop, decrypt, remove_key, times)

from ciphers import Aes, Salsa20, ChaCha20
from ciphers import SHA224, SHA256, SHA512, SHA512_224, SHA512_256
import sys

data_size = int(sys.argv[1])
times = int(sys.argv[2])
data = get_random_bytes(data_size)

hashes = (SHA224, SHA256, SHA512, SHA512_224, SHA512_256)

ciphers = {
        f'Salsa20-{key_len.value[0]}b-'
        f'{hash_algo.name if hash is not None else None}':
        cipher(key_len, hash_algo)
        for cipher in (Salsa20, ChaCha20)
        for key_len in cipher.KeyLen
        for hash_algo in hashes
}
ciphers.update({
        'AES128': Aes(Aes.KeyLen.AES_128),
        'AES192': Aes(Aes.KeyLen.AES_192),
        'AES256': Aes(Aes.KeyLen.AES_256),
})

for name, cipher in ciphers.items():
    test_symmetric(name, cipher, data, times)

