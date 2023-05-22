import random
from typing import Tuple
import hashlib
import time

# Fungsi untuk mengecek apakah a dan b bilangan yang relatif prima
def is_relative_prime(a: int, b: int) -> bool:
    while b:
        a, b = b, a % b
    
    return a == 1

with open('prime_list_1536.txt', 'r') as f:
    primes = list(map(int, f.read().split()))

# Fungsi untuk memilih nilai p, q, e secara random
def get_random_key() -> Tuple[int, int, int]:
    p, q, e = random.choices(primes, k=3)
    totient_n = (p - 1)*(q - 1)

    while not is_relative_prime(totient_n, e):
        p, q, e = random.choices(primes, k=3)

    return p, q, e

# Fungsi untuk menghitung invers modulo
def find_mod_inverse(e: int, totient_n: int) -> int:
    u1, u2, u3 = 1, 0, e
    v1, v2, v3 = 0, 1, totient_n
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3

    return u1 % totient_n

# Fungsi untuk menghitung invers modulo
def generate_public_key(p: int, q: int, e: int) -> Tuple[int, int]:
    return e, p * q

# Fungsi untuk menghitung dan membangkitkan private key
def generate_private_key(p: int, q: int, e: int) -> Tuple[int, int]:
    totient_n = (p - 1)*(q - 1)
    d = find_mod_inverse(e, totient_n)

    return d, p * q

# Fungsi untuk menghitung hash pesan menggunakan SHA-256
def hash_message(message: str) -> str:
    return hashlib.sha3_256(message.encode()).hexdigest()

# Fungsi untuk mengenkripsi pesan
def encrypt(message: str, d: int, n: int) -> str: 
    return ''.join(hex(pow(ord(m), d, n)) for m in message)

# Fungsi untuk mendekripsi pesan 
def decrypt(cipher: str, e: int, n: int) -> str:
    cipher = [int(x, 16) for x in cipher.split('0x')[1:]]

    return ''.join(chr(pow(c, e, n)) for c in cipher)

# Fungsi untuk menghasilkan tanda tangan digital
def create_signature(text: str, private_key: Tuple[int, int]) -> str:
    d, n = private_key

    return encrypt(hash_message(text), d, n)

if __name__ == '__main__':
    print("RSA Digital Signature\n")

    p, q, e = get_random_key()

    start_time = time.perf_counter()
    e, n = generate_public_key(p, q, e)
    d, n = generate_private_key(p, q, e)
    end_time = time.perf_counter()

    key_gen_time = (end_time-start_time)*1000

    print(f'Private key: {(d, n)}')
    print(f'Public key: {(e, n)}')
    print(f'Waktu key generation: {key_gen_time}ms\n')

    message = "II4031 Kriptografi dan Koding"
    print(f'Message: {message}')

    start_time = time.perf_counter()
    signature = create_signature(message, (d, n))
    end_time = time.perf_counter()
    
    signing_time = (end_time-start_time)*1000
    
    # print(f'Signature: {signature}')
    print(f'Waktu signing: {signing_time}ms\n')

    start_time = time.perf_counter()
    decrypted = decrypt(signature, e, n)
    valid = hash_message(message) == decrypted
    end_time = time.perf_counter()

    validation_time = (end_time-start_time)*1000

    print(f'Tanda tangan{"" if valid else " TIDAK"} VALID')
    print(f'Waktu validasi: {validation_time}ms\n')

    print(f'Total waktu: {key_gen_time+signing_time+validation_time}ms')