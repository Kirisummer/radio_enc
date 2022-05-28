from enum import Enum
from dataclasses import dataclass
from typing import NamedTuple, Callable
import math
import itertools

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes

from .cryptoutils import partition
from .Cipher import Cipher
from .hashes import HashAlgo

@dataclass
class Rsa(Cipher):
    class KeyLen(Enum):
        Rsa1024 = 1024
        Rsa2048 = 2048
        Rsa3072 = 3072

    key_len: KeyLen
    hash_algo: HashAlgo

    def encrypted_len(self, text_len):
        part_len = self.key_len.value // 8
        part_amount = math.ceil(text_len / part_len)
        return part_amount * part_len

    def encrypt(self, key, text):
        cipher = PKCS1_OAEP.new(key, hashAlgo=self.hash_algo.factory())
        return self._do_action(
                key,
                text,
                cipher.encrypt,
                self.part_len(key))

    def decrypt(self, key, ciphertext):
        cipher = PKCS1_OAEP.new(key, hashAlgo=self.hash_algo.factory())
        return self._do_action(
                key,
                ciphertext,
                cipher.decrypt, 
                Rsa.modulus_len(key))

    def _do_action(self, key, data, action, part_len):
        part_amount = math.ceil(len(data) / part_len)
        slices = itertools.repeat(part_len, part_amount)
        out_parts = []
        for part in partition(data, *slices):
            if part:
                out_parts.append(action(part))
        return b''.join(out_parts)

    def generate_key(self):
        return RSA.generate(self.key_len.value)

    def hash_key(self, key):
        hash_obj = self.hash_algo.factory()
        for val in map(long_to_bytes, (key.n, key.e)):
            hash_obj.update(val)
        return hash_obj.digest()

    def part_len(self, key):
        '''
        Get maximum length of text that the algo can encrypt and
        maximum length of ciphertext that can be decrypted
        '''
        return Rsa.modulus_len(key) - 2 * self.hash_algo.hash_len - 2

    @staticmethod
    def modulus_len(key):
        return len(long_to_bytes(key.n))

    @staticmethod
    def key_from_file(filename):
        with open(filename) as f:
            return RSA.importKey(f.read())

