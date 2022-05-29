from .SymmCipher import SymmCipher

class SalsaBase(SymmCipher):
    def __init__(self, key_len, nonce_len, hmac_hash: Algo = None):
        if hmac_hash:
            self.hash_algo = hmac_hash.factory
            hash_len = hmac_hash.hash_len
        else:
            self.hash_algo = None
            hash_len = 0
        super().__init__(key_len, nonce_len, hash_len)

    def encrypted_len(self, text_len):
        return text_len + 8

    def generate_tag(self, key, text):
        hmac = HMAC.new(key, msg=text, digestmod=self.hash_algo())
        return hmac.digest()

    def verify(self, tag, key, text):
        hmac = HMAC.new(key, msg=text, digestmod=self.hash_algo())
        hmac.verify(tag)

