from Crypto.Cipher import SALSA20
from enum import Enum

from .cryptoutils import partition
from .SymmCypher import SymmCypher

class Salsa20(SymmCipher):
    class KeyLen(Enum):
        B16: (16, 128, 8)
        B32: (32, 128, 8)

    def __init__(self, key_len: KeyLen):
        super().__init__(*key_len.value)

    def encrypt(self, key, text):
        cipher = Salsa20.new(key)
        return b''.join((cipher.nonce, ciphertext))

    def decrypt(self, key, ciphertext):
        nonce, ciphertext = partition(ciphertext, self.nonce_len)
        cipher = Salsa20.new(key, nonce=nonce)
        text = cipher.decrypt(ciphertext)
        return text

