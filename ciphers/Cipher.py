class Cipher:
    def __init__(self, *args, **kwargs):
        raise NotImplementedError()

    def encrypted_len(self, text_len):
        raise NotImplementedError()

    def encrypt(self, key, text):
        raise NotImplementedError()

    def decrypt(self, key, ciphertext):
        raise NotImplementedError()

