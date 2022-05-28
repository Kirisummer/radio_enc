from Crypto.Cipher import Salsa20 as SALSA20
from enum import Enum

from .cryptoutils import partition
from .SymmCipher import SymmCipher

class Salsa20(SymmCipher):
    class KeyLen(Enum):
        B16 = (16, 8)
        B32 = (32, 8)

    def __init__(self, key_len: KeyLen):
        super().__init__(*key_len.value)

    def encrypted_len(self, text_len):
        return text_len + 8

    def encrypt(self, key, text):
        cipher = SALSA20.new(key)
        ciphertext = cipher.encrypt(text)
        return b''.join((cipher.nonce, ciphertext))

    def decrypt(self, key, ciphertext):
        nonce, ciphertext = partition(ciphertext, self.nonce_len)
        cipher = SALSA20.new(key, nonce=nonce)
        text = cipher.decrypt(ciphertext)
        return text

