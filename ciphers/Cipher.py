class Cipher:
    def generate_key(self):
        raise NotImplementedError()

    def encrypt(self, key, text):
        raise NotImplementedError()

    def decrypt(self, key, ciphertext):
        raise NotImplementedError()

