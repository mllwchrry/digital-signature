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
    return sec1.SEC1Encoder.encode_public_key(point, compressed)


def sign_message(msg, sk):
    # Generate a random integer r
    r = random.randint(1, curve.q - 1)

    R = r * curve.G

    # Calculate the challenge e = H(R || pk || m)
    hash_input = serialize(R).hex() + serialize(sk * curve.G).hex() + msg
    e = int(hashlib.sha256(hash_input.encode()).hexdigest(), 16)

    s = (r + e * sk) % curve.q

    return R, s


def verify_signature(msg, signature, pk):
    R, s = signature

    # Calculate the challenge e = H(R || pk || m)
    hash_input = serialize(R).hex() + serialize(pk).hex() + msg
    e = int(hashlib.sha256(hash_input.encode()).hexdigest(), 16)

    return s * curve.G == R + e * pk

# # Example usage
# message = "Hello, world!"
# message2 = "Hello"
#
# # Generate keypair
# private_key, public_key = generate_keypair()
#
# # Sign the message
# signature = sign_message(message, private_key)
#
# # Verify the signature
# valid = verify_signature(message, signature, public_key)
#
# print(f"Message: {message}")
# print(f"Signature: {signature}")
# print(f"Is Valid: {valid}")
