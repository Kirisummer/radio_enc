import audioconf
from recorder import record_sound
from transmission import write_file
from ciphers import Rsa, Aes, Salsa20, SHA256
from encryption import encrypt, decrypt

import os
import sys
import timeit

def main(seconds):
    audioconf.init()

    data = record_sound(seconds)

    rsa = Rsa(Rsa.KeyLen.Rsa2048, SHA256)
    benchmark(data, rsa, rsa.generate_key(), rsa.hash_key,
            (Aes(Aes.KeyLen.AES_256), Salsa20(Salsa20.KeyLen.B32)),
            'RSA_Aes256_Salsa')
    benchmark(data, rsa, rsa.generate_key(), rsa.hash_key,
            (Aes(Aes.KeyLen.AES_128), Salsa20(Salsa20.KeyLen.B32)),
            'RSA_Aes128_Salsa')
    benchmark(data, rsa, rsa.generate_key(), rsa.hash_key,
            (Salsa20(Salsa20.KeyLen.B32), Aes(Aes.KeyLen.AES_256)),
            'RSA_Salsa_Aes256')
    benchmark(data, rsa, rsa.generate_key(), rsa.hash_key,
            (Salsa20(Salsa20.KeyLen.B32), Aes(Aes.KeyLen.AES_128)),
            'RSA_Salsa_Aes128')

    audioconf.terminate()

def benchmark(data, key_cipher, key, key_hash, ciphers, out_name):
    print('#', out_name, '###########################################')

    # Час
    timer('Encryption', lambda: encrypt(key_cipher, key, key_hash, ciphers, data), 10)
    enc_data = encrypt(key_cipher, key, key_hash, ciphers, data)
    timer('Decryption', lambda: decrypt(key_cipher, key, key_hash, ciphers, enc_data), 10)
    dec_data = decrypt(key_cipher, key, key_hash, ciphers, enc_data)

    # Запис до файлів
    write_files(out_name, data, enc_data, dec_data)

    # Розмір даних
    print(f'Data size:', len(data), sep='\t')
    print(f'Encrypted size:', len(enc_data), sep='\t')
    print(f'Increase:', len(enc_data) * 100 / len(data) - 100, sep='\t', end='%\n')

    # Криптостійкість (TODO: однорідність)
    zeroes, ones = count_bin(enc_data)
    print(f'0: {zeroes}, 1: {ones}')
    print(f'data == dec_data: {data == dec_data}')

    print('\n')

def timer(label, action, times):
    avg = timeit.Timer(action).timeit(number=times) / times
    print(f'{label} over {times} time(s): {avg}s')

def write_files(out_name, data, enc_data, dec_data):
    os.mkdir(out_name)
    write_file(data,     f'{out_name}/rec.wav')
    write_file(enc_data, f'{out_name}/enc.wav')
    write_file(dec_data, f'{out_name}/dev.wav')

def count_bin(data):
    zeroes = ones = 0
    for byte in data:
        for mask in (0b1 << shift for shift in range(8)):
            if byte & mask:
                ones += 1
            else:
                zeroes += 1
    return zeroes, ones

if __name__ == '__main__':
    main(int(sys.argv[1]))
