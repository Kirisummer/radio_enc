from Crypto.Cipher import ChaCha20 as CHACHA20
from enum import Enum

from .cryptoutils import partition
from .SymmCipher import SymmCipher

class ChaCha20(SymmCipher):
    class KeyLen(Enum):
        B32_8 =  (32, 8)
        B32_12 = (32, 12)

    def __init__(self, key_len: KeyLen):
        super().__init__(*key_len.value)

    def encrypted_len(self, text_len):
        return text_len + 8

    def encrypt(self, key, text):
        cipher = CHACHA20.new(key)
        ciphertext = cipher.encrypt(text)
        return b''.join((cipher.nonce, ciphertext))

    def decrypt(self, key, ciphertext):
        nonce, ciphertext = partition(ciphertext, self.nonce_len)
        cipher = CHACHA20.new(key, nonce=nonce)
        text = cipher.decrypt(ciphertext)
        return text

