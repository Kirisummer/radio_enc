from Crypto.Cipher import AES
from enum import Enum

from .SymmCipher import SymmCipher
from .cryptoutils import partition

class Aes(SymmCipher):
    class KeyLen(Enum):
        AES_128 = (16, 16)
        AES_192 = (24, 16)
        AES_256 = (32, 16)

    def __init__(self, key_len: KeyLen, tag_len=16):
        self.tag_len = tag_len
        super().__init__(*key_len.value)

    def encrypted_len(self, text_len):
        return self.key_len + text_len

    def encrypt(self, key, text):
        cipher = AES.new(key, mode=AES.MODE_EAX, mac_len=self.tag_len)
        ciphertext, tag = cipher.encrypt_and_digest(text)
        return b''.join((cipher.nonce, tag, ciphertext))

    def decrypt(self, key, ciphertext):
        nonce, tag, ciphertext = \
                            partition(ciphertext, self.nonce_len, self.tag_len)
        cipher = AES.new(key, mode=AES.MODE_EAX, nonce=nonce)
        text = cipher.decrypt(ciphertext)
        cipher.verify(tag)
        return text

