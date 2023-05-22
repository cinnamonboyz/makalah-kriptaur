import hashlib
import random
import time

# Definisikan parameter kurva eliptik (secp256k1)
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

# Fungsi untuk menghitung invers modulo
def mod_inverse(a, m):
    if a < 0 or m <= a:
        a = a % m
    c, d = a, m
    uc, vc, ud, vd = 1, 0, 0, 1
    while c != 0:
        q, c, d = divmod(d, c) + (c,)
        uc, vc, ud, vd = ud - q * uc, vd - q * vc, uc, vc
    if ud > 0:
        return ud
    else:
        return ud + m

# Fungsi untuk menghitung titik hasil perkalian skalar pada kurva eliptik
def point_multiplication(k, P):
    if k == 0:
        return None
    elif k == 1:
        return P
    else:
        Q = point_multiplication(k // 2, P)
        Q = point_addition(Q, Q)
        if k % 2 == 1:
            Q = point_addition(Q, P)
        return Q

# Fungsi untuk menghitung hasil penjumlahan dua titik pada kurva eliptik
def point_addition(P, Q):
    if P is None:
        return Q
    elif Q is None:
        return P
    else:
        if P[0] == Q[0] and P[1] == Q[1]:
            lam = (3 * P[0] * P[0] + a) * mod_inverse(2 * P[1], p)
        else:
            lam = (Q[1] - P[1]) * mod_inverse(Q[0] - P[0], p)
        x = (lam * lam - P[0] - Q[0]) % p
        y = (lam * (P[0] - x) - P[1]) % p
        return (x, y)

# Fungsi untuk membangkitkan private key secara random
def generate_private_key():
    return random.randint(1, n)

# Fungsi untuk membangkitkan public key berdasarkan private key
def generate_public_key(private_key):
    return point_multiplication(private_key, (Gx, Gy))

# Fungsi untuk menghitung hash pesan menggunakan SHA-256
def hash_message(message):
    sha3 = hashlib.sha3_256()
    sha3.update(message.encode('utf-8'))
    return int(sha3.hexdigest(), 16)

# Fungsi untuk menghasilkan tanda tangan digital
def sign_message(private_key, message):
    k = random.randint(1, n)
    R = point_multiplication(k, (Gx, Gy))
    r = R[0] % n
    if r == 0:
        return sign_message(private_key, message)
    else:
        s = (mod_inverse(k, n) * (hash_message(message) + private_key * r)) % n
        if s == 0:
            return sign_message(private_key, message)
        else:
            return (r, s)

# Fungsi untuk memverifikasi tanda tangan digital
def verify_signature(public_key, message, signature):
    r, s = signature
    if r < 1 or r > n - 1 or s < 1 or s > n - 1:
        return False
    else:
        w = mod_inverse(s, n)
        u1 = (hash_message(message) * w) % n
        u2 = (r * w) % n
        X = point_addition(point_multiplication(u1, (Gx, Gy)), point_multiplication(u2, public_key))
        if X is None:
            return False
        else:
            return r == X[0] % n

if __name__ == '__main__':
    print("ECC Digital Signature\n")
    start_time = time.perf_counter()
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    end_time = time.perf_counter()

    key_gen_time = (end_time-start_time)*1000

    print(f'Private key: {private_key}')
    print(f'Public key: {public_key}')
    print(f'Waktu key generation: {key_gen_time}ms\n')

    message = 'II4031 Kriptografi dan Koding'

    start_time = time.perf_counter()
    signature = sign_message(private_key, message)
    end_time = time.perf_counter()

    print(f'Message: {message}')

    signing_time = (end_time-start_time)*1000

    print("r =", signature[0])
    print("s =", signature[1])
    print(f'Waktu tanda tangan: {signing_time}ms\n')

    start_time = time.perf_counter()
    valid = verify_signature(public_key, message, signature)
    end_time = time.perf_counter()

    validation_time = (end_time-start_time)*1000

    print(f'Tanda tangan{"" if valid else " TIDAK"} VALID')
    print(f'Waktu validasi: {validation_time}ms\n')

    print(f'Total waktu yang diperlukan: {key_gen_time+signing_time+validation_time}ms')
