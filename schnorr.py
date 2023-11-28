import hashlib
import random
from fastecdsa import curve
from fastecdsa.encoding import sec1

curve = curve.secp256k1


def generate_keypair():
    while True:
        # generating private key (random integer in the range [1, curve.q-1])
        sk = random.randint(1, curve.q - 1)

        # generating public key (multiply the base point by the private key)
        pk = curve.G * sk
        if curve.is_point_on_curve((pk.x, pk.y)):
            break
    return sk, pk


# serializes a point according to the SEC1 standard (both compressed and uncompressed format)
def serialize(point, compressed=False):
    return sec1.SEC1Encoder.encode_public_key(point, compressed).hex()


def generate_nonce():
    while True:
        # Generate a random integer r
        r = random.randint(1, curve.q - 1)

        R = r * curve.G
        if curve.is_point_on_curve((R.x, R.y)):
            break

    return r, R


def generate_shared_pk(pks):
    serialized_pks = list(map(serialize, pks))
    hash_input = "".join(serialized_pks)
    l = hashlib.sha256(hash_input.encode()).hexdigest()
    a = [None] * len(pks)

    for i in range(len(serialized_pks)):
        hash_input_a = str(l) + serialized_pks[i]
        a[i] = int(hashlib.sha256(hash_input_a.encode()).hexdigest(), 16)

    X = a[0] * pks[0]
    for i in range(1, len(serialized_pks)):
        X += a[i] * pks[i]

    return X, a


def generate_shared_nonce(nonces):
    R = nonces[0]
    for i in range(1, len(nonces)):
        R += nonces[i]
    return R


def generate_challenge(R, X, m):
    hash_input = serialize(R) + serialize(X) + m
    e = int(hashlib.sha256(hash_input.encode()).hexdigest(), 16)
    return e


def generate_s_for_musig(r, sk, a, e):
    return r + sk * a * e


def aggregate_signature(signatures):
    return sum(signatures)


def sign(msg, sk):
    r, R = generate_nonce()

    # Calculate the challenge e = H(R || pk || m)
    hash_input = serialize(R) + serialize(sk * curve.G) + msg
    e = int(hashlib.sha256(hash_input.encode()).hexdigest(), 16)

    s = (r + e * sk) % curve.q

    return R, s


def muSig(sks, pks, rs, Rs, msg):
    X, a = generate_shared_pk(pks)
    R = generate_shared_nonce(Rs)
    e = generate_challenge(R, X, msg)

    signatures = [None] * len(pks)
    for i in range(len(pks)):
        signatures[i] = generate_s_for_musig(rs[i], sks[i], a[i], e)

    s = aggregate_signature(signatures)

    return R, s


def verify(msg, signature, pk):
    R, s = signature

    # Calculate the challenge e = H(R || pk || m)
    hash_input = serialize(R) + serialize(pk) + msg
    e = int(hashlib.sha256(hash_input.encode()).hexdigest(), 16)

    return s * curve.G == R + e * pk
