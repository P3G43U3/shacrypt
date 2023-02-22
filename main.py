constants   = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
hash_values = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

def rotr(x, n):
    return (x >> n) | (x << (32 - n))

def sha256(inpt):
    w = [0] * 64
    a, b, c, d, e, f, g, h = hash_values

    inpt += b'\x80'
    while len(inpt) % 64 != 56:
        inpt += b'\x00'
    inpt += len(inpt).to_bytes(8, byteorder='big')

    for i in range(0, len(inpt), 64):
        for j in range(16):
            w[j] = int.from_bytes(inpt[i+j*4:i+j*4+4], byteorder='big')
        for j in range(16, 64):
            s0 = rotr(w[j-15], 7) ^ rotr(w[j-15], 18) ^ (w[j-15] >> 3)
            s1 = rotr(w[j-2], 17) ^ rotr(w[j-2], 19) ^ (w[j-2] >> 10)
            w[j] = (w[j-16] + s0 + w[j-7] + s1) % 2**32
    
        a, b, c, d, e, f, g, h = hash_values
    
        for j in range(64):
            s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + s1 + ch + constants[j] + w[j]) % 2**32
            s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) % 2**32
        
            h = g
            g = f
            f = e
            e = (d + temp1) % 2**32
            d = c
            c = b
            b = a
            a = (temp1 + temp2) % 2**32
    
        hash_values[0] = (hash_values[0] + a) % 2**32
        hash_values[1] = (hash_values[1] + b) % 2**32
        hash_values[2] = (hash_values[2] + c) % 2**32
        hash_values[3] = (hash_values[3] + d) % 2**32
        hash_values[4] = (hash_values[4] + e) % 2**32
        hash_values[5] = (hash_values[5] + f) % 2**32
        hash_values[6] = (hash_values[6] + g) % 2**32
        hash_values[7] = (hash_values[7] + h) % 2**32

    return b''.join([i.to_bytes(4, byteorder='big') for i in hash_values])

def encrypt(msg: str):
    value = ''.join(f'{i:02x}' for i in sha256(msg.encode("utf-8")))
    return value
