from enum import Enum
from dataclasses import dataclass
from Crypto.Random import get_random_bytes

from .Cipher import Cipher
from .cryptoutils import partition

@dataclass
class SymmCipher(Cipher):
    key_len: int
    nonce_len: int
    tag_len: int

    def _partition(self, ciphertext):
        return partition(ciphertext, self.nonce_len, self.tag_len)

    def generate_key(self):
        return get_random_bytes(self.key_len)

