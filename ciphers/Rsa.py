from enum import Enum
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA224, SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
import math
import itertools

from .cryptoutils import partition
from .Cipher import Cipher

class Hash(NamedTuple):
    factory: Callable['SHA']
    hash_len: int

@dataclass
class Rsa(Cipher):
    class KeyLen(Enum):
        Rsa1024 = 1024
        Rsa2048 = 2048
        Rsa3072 = 3072

    class HashAlgo(Enum):
        SHA224 =     Hash(lambda: SHA224.new(), 28)
        SHA256 =     Hash(lambda: SHA256.new(), 32)
        SHA512 =     Hash(lambda: SHA512.new(), 64)
        SHA512_224 = Hash(lambda: SHA512.new(truncate=224), 28)
        SHA512_256 = Hash(lambda: SHA512.new(truncate=256), 32)

    hash_algo: HashAlgo

    def encrypt(self, key, text):
        cipher = PKCS1_OAEP.new(key, hashAlgo=self.hash_algo.factory())
        return self._do_action(key, ciphertext, cipher.encrypt)

    def decrypt(self, key, ciphertext):
        cipher = PKCS1_OAEP.new(key, hashAlgo=self.hash_algo.factory())
        return self._do_action(key, ciphertext, cipher.decrypt)

    def _do_action(self, key, data, action):
        part_len = self.part_len(key)
        part_amount = math.ceil(len(data) / part_len)
        slices = itertools.repeat(part_len, part_amount)
        out_parts = []
        for part in partition(data, slices):
            if part:
                parts.append(action(part))
        return b''.join(parts)

    @staticmethod
    def generate_key(key_len: KeyLen):
        return RSA.generate(key_len.value)

    @staticmethod
    def key_from_file(filename):
        with open(filename) as f:
            return RSA.importKey(f.read())

    def hash_key(self, key):
        hash_obj = self.hash_algo.factory()
        for val in map(long_to_bytes, (key.n, key.e)):
            hash_obj.update(val)
        return hash_obj.digest()

    @cache
    def part_len(self, key):
        '''
        Get maximum length of text that the algo can encrypt and
        maximum length of ciphertext that can be decrypted
        '''
        modulus_len = len(long_to_bytes(key.n))
        return modulus_len - 2 * self.hash_algo.hash_len - 2

