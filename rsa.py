import random
import math


def is_prime(n, k = 5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    # Miller-Rabin primality test
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bit_length):
    while True:
        n = random.randint(2 ** (bit_length - 1), 2 ** bit_length)
        if is_prime(n):
            return n


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def gen_keypair(bit_length):
    p = gen_prime(bit_length)
    q = gen_prime(bit_length)
    n = p * q
    m = (p - 1) * (q - 1)

    while True:
        e = random.randint(2, m - 1)
        if gcd(e, m) == 1:
            break

    d = pow(e, -1, m)

    return (n, e), (n, d)


def sign(msg, sk):
    n, d = sk
    if isinstance(msg, str):
        msg = int.from_bytes(msg.encode(), 'big')
    return pow(msg, d, n)


def verify(msg, s, pk):
    n, e = pk
    decrypted_signature = pow(s, e, n)
    if isinstance(msg, str):
        msg = int.from_bytes(msg.encode(), 'big')
    return decrypted_signature == msg


# Example usage
message = "Hello, world!"
# wrong_message = 'Hello, world'
sk, pk = gen_keypair(1024)
signature = sign(message, sk)
is_valid = verify(message, signature, pk)

print(f"Message: {message}")
print(f"Signature: {signature}")
print(f"Is Valid: {is_valid}")
