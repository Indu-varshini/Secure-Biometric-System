import numpy as np
import hashlib

class BloomFilter:
    def __init__(self, size=256, hash_count=3):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = np.zeros(size, dtype=int)

    def _hashes(self, data):
        hashes = []
        for i in range(self.hash_count):
            hash_val = hashlib.sha256((str(data) + str(i)).encode()).hexdigest()
            index = int(hash_val, 16) % self.size
            hashes.append(index)
        return hashes

    def add(self, binary_template):
        for bit in binary_template:
            if bit == 1:
                for index in self._hashes(bit):
                    self.bit_array[index] = 1

    def get_filter(self):
        return self.bit_array
