from Crypto.Cipher import ChaCha20 as CHACHA20
from Crypto.Random import get_random_bytes
from enum import Enum

from .cryptoutils import partition
from .SalsaBase import SalsaBase
from .hashes import HashAlgo

class ChaCha20(SalsaBase):
    class KeyLen(Enum):
        B32_8 =  (32, 8)
        B32_12 = (32, 12)

    def __init__(self, key_len: KeyLen, hmac_hash: HashAlgo):
        super().__init__(*key_len.value, hmac_hash)

    def encrypted_len(self, text_len):
        return text_len + 8

    def encrypt(self, key, text):
        nonce = get_random_bytes(self.nonce_len)
        cipher = CHACHA20.new(key=key, nonce=nonce)
        ciphertext = cipher.encrypt(text)
        if self.hash_algo:
            tag = self.generate_tag(key, text)
        else:
            tag = b''
        return b''.join((cipher.nonce, tag, ciphertext))

    def decrypt(self, key, ciphertext):
        nonce, tag, ciphertext = self._partition(ciphertext)
        cipher = CHACHA20.new(key=key, nonce=nonce)
        text = cipher.decrypt(ciphertext)
        if self.hash_algo:
            self.verify(tag, key, text)
        return text

