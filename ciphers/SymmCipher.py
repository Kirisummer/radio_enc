from dataclasses import dataclass
from Crypto.Random import get_random_bytes

from .Cipher import Cipher

@dataclass
class SymmCipher(Cipher):
    key_len: int
    nonce_len: int

    def generate_key(self):
        return get_random_bytes(self.key_len)

