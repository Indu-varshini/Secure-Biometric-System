import numpy as np

class FPE:
    def __init__(self, key=7):
        self.key = key  # secret key

    def encrypt(self, binary_template):
        encrypted = [(bit ^ (self.key % 2)) for bit in binary_template]
        return encrypted

    def decrypt(self, encrypted_template):
        decrypted = [(bit ^ (self.key % 2)) for bit in encrypted_template]
        return decrypted
