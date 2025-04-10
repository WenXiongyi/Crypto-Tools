from Crypto.Util.number import bytes_to_long, long_to_bytes

class RC6Encryption:
    def __init__(self, key, w=32, r=20):
        self.w = w  # word size in bits
        self.r = r  # number of rounds
        self.key = key
        self.T = 2 * (r + 1)  # size of table S
        self.w4 = w // 4
        self.mask = (1 << w) - 1
        self.S = self._expand_key()

    def _expand_key(self):
        bytes_per_word = self.w // 8
        key_bytes = self.key
        if len(key_bytes) == 0:
            key_bytes = b'\x00' * bytes_per_word
        
        c = len(key_bytes) // bytes_per_word
        if len(key_bytes) % bytes_per_word:
            c += 1
            key_bytes += b'\x00' * (c * bytes_per_word - len(key_bytes))
        
        L = []
        for i in range(0, len(key_bytes), bytes_per_word):
            L.append(bytes_to_long(key_bytes[i:i+bytes_per_word]))
        
        P = 0xB7E15163
        Q = 0x9E3779B9
        
        S = [(P + i * Q) & self.mask for i in range(self.T)]
        
        A = B = i = j = 0
        v = 3 * max(c, self.T)
        
        for _ in range(v):
            A = S[i] = ((S[i] + A + B) << 3) & self.mask
            B = L[j] = ((L[j] + A + B) << (A + B)) & self.mask
            i = (i + 1) % self.T
            j = (j + 1) % c
        
        return S

    def _encrypt_block(self, block):
        bytes_per_word = self.w // 8
        A = bytes_to_long(block[:bytes_per_word])
        B = bytes_to_long(block[bytes_per_word:2*bytes_per_word])
        C = bytes_to_long(block[2*bytes_per_word:3*bytes_per_word])
        D = bytes_to_long(block[3*bytes_per_word:4*bytes_per_word])
        
        B = (B + self.S[0]) & self.mask
        D = (D + self.S[1]) & self.mask
        
        for i in range(1, self.r + 1):
            t = ((B * (2 * B + 1)) << self.w4) & self.mask
            u = ((D * (2 * D + 1)) << self.w4) & self.mask
            A = (((A ^ t) << u) | ((A ^ t) >> (self.w - u))) & self.mask
            C = (((C ^ u) << t) | ((C ^ u) >> (self.w - t))) & self.mask
            
            A, B, C, D = B, C, D, A
        
        A = (A + self.S[2*self.r + 2]) & self.mask
        C = (C + self.S[2*self.r + 3]) & self.mask
        
        return b''.join(map(lambda x: long_to_bytes(x, bytes_per_word), [A, B, C, D]))

    def _decrypt_block(self, block):
        bytes_per_word = self.w // 8
        A = bytes_to_long(block[:bytes_per_word])
        B = bytes_to_long(block[bytes_per_word:2*bytes_per_word])
        C = bytes_to_long(block[2*bytes_per_word:3*bytes_per_word])
        D = bytes_to_long(block[3*bytes_per_word:4*bytes_per_word])
        
        C = (C - self.S[2*self.r + 3]) & self.mask
        A = (A - self.S[2*self.r + 2]) & self.mask
        
        for i in range(self.r, 0, -1):
            A, B, C, D = D, A, B, C
            
            u = ((D * (2 * D + 1)) << self.w4) & self.mask
            t = ((B * (2 * B + 1)) << self.w4) & self.mask
            C = ((C >> t) | (C << (self.w - t))) & self.mask
            C = C ^ u
            A = ((A >> u) | (A << (self.w - u))) & self.mask
            A = A ^ t
        
        D = (D - self.S[1]) & self.mask
        B = (B - self.S[0]) & self.mask
        
        return b''.join(map(lambda x: long_to_bytes(x, bytes_per_word), [A, B, C, D]))

    def encrypt(self, data):
        block_size = self.w * 4 // 8
        padding = block_size - (len(data) % block_size)
        padded_data = data + bytes([padding] * padding)
        
        result = b''
        for i in range(0, len(padded_data), block_size):
            block = padded_data[i:i+block_size]
            result += self._encrypt_block(block)
        return result

    def decrypt(self, data):
        block_size = self.w * 4 // 8
        result = b''
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            result += self._decrypt_block(block)
        
        padding = result[-1]
        return result[:-padding] 