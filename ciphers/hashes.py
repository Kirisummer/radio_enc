from typing import NamedTuple, Callable
import Crypto.Hash.SHA224
import Crypto.Hash.SHA256
import Crypto.Hash.SHA512

class HashAlgo(NamedTuple):
    factory: Callable[[], 'SHA']
    hash_len: int
    name: str

    def digest(self, data):
        hash_obj = self.factory()
        hash_obj.update(data)
        return hash_obj.digest()

SHA224 = HashAlgo(
        lambda: Crypto.Hash.SHA224.new(), 28, 'SHA224')
SHA256 = HashAlgo(
        lambda: Crypto.Hash.SHA256.new(), 32, 'SHA256')
SHA512 = HashAlgo(
        lambda: Crypto.Hash.SHA512.new(), 64, 'SHA512')
SHA512_224 = HashAlgo(
        lambda: Crypto.Hash.SHA512.new(truncate='224'), 28, 'SHA512/224')
SHA512_256 = HashAlgo(
        lambda: Crypto.Hash.SHA512.new(truncate='256'), 32, 'SHA512/256')
