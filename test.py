import unittest
from fastecdsa import curve
from rsa import gen_keypair as rsa_gen_keypair, sign as rsa_sign, verify as rsa_verify
from ecdsa import gen_keypair as ecdsa_gen_keypair, sign as ecdsa_sign, verify as ecdsa_verify
from schnorr import generate_keypair, generate_nonce, generate_shared_pk, sign as schnorr_sign, muSig, verify as schnorr_verify

curve = curve.secp256k1


class TestDigitalSignatures(unittest.TestCase):

    # should verify the correct RSA signature properly
    def test_rsa_verify(self):
        message = "Hello, world!"
        sk, pk = rsa_gen_keypair(1024)
        signature = rsa_sign(message, sk)
        self.assertTrue(rsa_verify(message, signature, pk))

    # should verify the incorrect RSA signature (changed message) properly
    def test_rsa_verify_invalid_message(self):
        message = "Hello, world!"
        wrong_message = 'Hello, world'
        sk, pk = rsa_gen_keypair(1024)
        signature = rsa_sign(message, sk)
        self.assertTrue(rsa_verify(message, signature, pk))
        self.assertFalse(rsa_verify(wrong_message, signature, pk))

    # should verify the incorrect RSA signature (changed public key) properly
    def test_rsa_verify_invalid_pk(self):
        message = "Hello, world!"
        sk, pk = rsa_gen_keypair(1024)
        _, pk1 = rsa_gen_keypair(1024)
        signature = rsa_sign(message, sk)
        self.assertTrue(rsa_verify(message, signature, pk))
        self.assertFalse(rsa_verify(message, signature, pk1))

    # should verify the correct ECDSA signature properly
    def test_ecdsa_verify(self):
        message = "Hello, world!"
        sk, pk = ecdsa_gen_keypair()
        signature = ecdsa_sign(message, sk)
        self.assertTrue(ecdsa_verify(message, signature, pk))

    # should verify the incorrect ECDSA signature (changed message) properly
    def test_ecdsa_verify_invalid_message(self):
        message = "Hello, world!"
        wrong_message = "Hello, world"
        sk, pk = ecdsa_gen_keypair()
        signature = ecdsa_sign(message, sk)
        self.assertFalse(ecdsa_verify(wrong_message, signature, pk))

    # should verify the incorrect ECDSA signature (changed public key) properly
    def test_ecdsa_verify_invalid_pk(self):
        message = "Hello, world!"
        sk, pk = ecdsa_gen_keypair()
        _, pk1 = ecdsa_gen_keypair()
        signature = ecdsa_sign(message, sk)
        self.assertFalse(ecdsa_verify(message, signature, pk1))

    # should verify the correct Schnorr single signature properly
    def test_schnorr_single_verify(self):
        message = "Hello, world!"
        sk, pk = generate_keypair()
        signature = schnorr_sign(message, sk)
        self.assertTrue(schnorr_verify(message, signature, pk))

    # should verify the incorrect Schnorr single signature (changed message) properly
    def test_schnorr_single_verify_invalid_message(self):
        message = "Hello, world!"
        wrong_message = "Hello, world"
        sk, pk = generate_keypair()
        signature = schnorr_sign(message, sk)
        self.assertFalse(schnorr_verify(wrong_message, signature, pk))

    # should verify the incorrect Schnorr single signature (changed public key) properly
    def test_schnorr_single_verify_invalid_pk(self):
        message = "Hello, world!"
        sk, pk = generate_keypair()
        _, pk1 = generate_keypair()
        signature = schnorr_sign(message, sk)
        self.assertFalse(schnorr_verify(message, signature, pk1))

    # should verify the correct Schnorr MuSig signature properly
    def test_schnorr_musig_verify(self):
        message = "Hello, world!"

        private_key1, public_key1 = generate_keypair()
        private_key2, public_key2 = generate_keypair()
        private_key3, public_key3 = generate_keypair()
        private_nonce1, public_nonce1 = generate_nonce()
        private_nonce2, public_nonce2 = generate_nonce()
        private_nonce3, public_nonce3 = generate_nonce()

        private_keys = [private_key1, private_key2, private_key3]
        public_keys = [public_key1, public_key2, public_key3]
        private_nonces = [private_nonce1, private_nonce2, private_nonce3]
        public_nonces = [public_nonce1, public_nonce2, public_nonce3]

        signature = muSig(private_keys, public_keys, private_nonces, public_nonces, message)
        shared_pk, _ = generate_shared_pk(public_keys)
        self.assertTrue(schnorr_verify(message, signature, shared_pk))

    # should verify the incorrect Schnorr MuSig signature (changed message) properly
    def test_schnorr_musig_verify_invalid_message(self):
        message = "Hello, world!"
        wrong_message = "Hello, world"

        private_key1, public_key1 = generate_keypair()
        private_key2, public_key2 = generate_keypair()
        private_key3, public_key3 = generate_keypair()
        private_nonce1, public_nonce1 = generate_nonce()
        private_nonce2, public_nonce2 = generate_nonce()
        private_nonce3, public_nonce3 = generate_nonce()

        private_keys = [private_key1, private_key2, private_key3]
        public_keys = [public_key1, public_key2, public_key3]
        private_nonces = [private_nonce1, private_nonce2, private_nonce3]
        public_nonces = [public_nonce1, public_nonce2, public_nonce3]

        signature = muSig(private_keys, public_keys, private_nonces, public_nonces, message)
        shared_pk, _ = generate_shared_pk(public_keys)
        self.assertFalse(schnorr_verify(wrong_message, signature, shared_pk))

    # should verify the incorrect Schnorr MuSig signature (changed public key) properly
    def test_schnorr_musig_verify_invalid_pk(self):
        message = "Hello, world!"

        private_key1, public_key1 = generate_keypair()
        private_key2, public_key2 = generate_keypair()
        private_key3, public_key3 = generate_keypair()
        private_nonce1, public_nonce1 = generate_nonce()
        private_nonce2, public_nonce2 = generate_nonce()
        private_nonce3, public_nonce3 = generate_nonce()

        private_keys = [private_key1, private_key2, private_key3]
        public_keys = [public_key1, public_key2, public_key3 - public_key1 - public_key2]
        private_nonces = [private_nonce1, private_nonce2, private_nonce3]
        public_nonces = [public_nonce1, public_nonce2, public_nonce3]

        signature = muSig(private_keys, public_keys, private_nonces, public_nonces, message)
        shared_pk, _ = generate_shared_pk(public_keys)
        self.assertFalse(schnorr_verify(message, signature, shared_pk))
