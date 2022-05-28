import audioconf
from recorder import record_sound
from transmission import write_file
from ciphers import Rsa, Aes, Salsa20, SHA256
from encryption import encrypt, decrypt

import sys

def main(filename, seconds):
    audioconf.init()

    rsa = Rsa(Rsa.KeyLen.Rsa2048, SHA256)
    key = rsa.generate_key()
    ciphers = Aes(Aes.KeyLen.AES_256), Salsa20(Salsa20.KeyLen.B32)

    data = record_sound(seconds)
    enc_data = encrypt(rsa, key, rsa.hash_key, ciphers, data)
    dec_data = decrypt(rsa, key, rsa.hash_key, ciphers, enc_data)

    write_file(data, filename + '.wav')
    write_file(enc_data, filename + '.enc.wav')
    write_file(dec_data, filename + '.dec.wav')

    audioconf.terminate()
    zeroes, ones = count_bin(enc_data)

    print(f'0: {zeroes}, 1: {ones}')
    print(f'data == dec_data: {data == dec_data}')

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
    main(sys.argv[1], int(sys.argv[2]))
