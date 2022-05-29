from Crypto.Cipher import Salsa20 as SALSA20
from enum import Enum

from .cryptoutils import partition
from .SalsaBase import SalsaBase
from .hashes import HashAlgo

class Salsa20(SalsaBase):
    class KeyLen(Enum):
        B16 = (16, 8)
        B32 = (32, 8)

    def __init__(self, key_len: KeyLen, hmac_hash: HashAlgo = None):
        super().__init__(*key_len.value, hmac_hash)

    def encrypted_len(self, text_len):
        return text_len + 8

    def encrypt(self, key, text):
        cipher = SALSA20.new(key)
        ciphertext = cipher.encrypt(text)
        if self.hash_algo:
            tag = self.generate_tag(key, text)
        else:
            tag = b''
        return b''.join((cipher.nonce, tag, ciphertext))

    def decrypt(self, key, ciphertext):
        nonce, tag, ciphertext = self._partition(ciphertext)
        cipher = SALSA20.new(key, nonce=nonce)
        text = cipher.decrypt(ciphertext)
        if self.hash_algo:
            self.verify(tag, key, text)
        return text

