import audioconf
from recorder import record_sound
from transmission import write_file
from encryption import encrypt, rsa_key_from_file
from decryption import decrypt

import sys

def main(filename, pub_key_file, seconds):
    audioconf.init()

    key = rsa_key_from_file(pub_key_file)
    data = record_sound(seconds)
    enc_data = encrypt(key, data)
    dec_data = decrypt(key, enc_data)

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
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]))
