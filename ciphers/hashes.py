from typing import NamedTuple, Callable
import Crypto.Hash

class HashAlgo(NamedTuple):
    factory: Callable[[], 'SHA']
    hash_len: int

    def digest(self, data):
        hash_obj = self.factory()
        hash_obj.update(data)
        return hash_obj.digest()

    def __len__(self):
        return hash_len

SHA224     = HashAlgo(lambda: Crypto.Hash.SHA224.new(), 28)
SHA256     = HashAlgo(lambda: Crypto.Hash.SHA256.new(), 32)
SHA512     = HashAlgo(lambda: Crypto.Hash.SHA512.new(), 64)
SHA512_224 = HashAlgo(lambda: Crypto.Hash.SHA512.new(truncate=224), 28)
SHA512_256 = HashAlgo(lambda: Crypto.Hash.SHA512.new(truncate=256), 32)
