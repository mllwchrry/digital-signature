import hashlib
import random
from fastecdsa import curve

curve = curve.secp256k1


def gen_keypair():
    while True:
        # generating private key (random integer in the range [1, curve.q-1])
        sk = random.randint(1, curve.q - 1)

        # generating public key (multiply the base point by the private key)
        pk = curve.G * sk
        if curve.is_point_on_curve((pk.x, pk.y)):
            break
    return sk, pk


def sign(msg, sk):

    while True:
        # hashing the message
        hash = hashlib.sha256(msg.encode()).digest()

        n = curve.q
        k = random.randint(1, n - 1)

        p = curve.G * k
        x1, y1 = p.x, p.y

        r = x1 % n
        if r != 0:
            break

    s = (pow(k, -1, n) * (int.from_bytes(hash, 'big') + sk * r)) % n

    return r, s


def verify(msg, sig, pk):
    # hashing the message
    msg_hash = hashlib.sha256(msg.encode()).digest()

    n = curve.q
    r, s = sig
    w = pow(s, -1, n)

    u1 = (int.from_bytes(msg_hash, 'big') * w) % n
    u2 = (r * w) % n

    p = u1 * curve.G + u2 * pk
    x1, y1 = p.x, p.y

    v = x1 % n

    return v == r
