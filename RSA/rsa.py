from number_theory_stuff import mulinv, random_prime, random_coprime
import message
from transformations import *


def generate_keypair(bits):
    p = random_prime(bits//2)
    q = random_prime(bits//2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = random_coprime(phi)  # alternative e = 65537

    d = mulinv(e, phi)

    private = (d, n)
    public = (e, n)
    return private, public


class Message(message.Message):

    def encrypt(self, key):
        e, n = key
        if self.int() >= n:
            raise RuntimeError('Message must be smaller than the modulus')
        encrypted = pow(self.int(), e, n)
        self.msg = int_to_bytes(encrypted)

    def decrypt(self, key):
        d, n = key
        decrypted = pow(self.int(), d, n)
        self.msg = int_to_bytes(decrypted)

    def sign(self, key):
        d, n = key
        hashed = self.hash()
        as_int = hex_to_int(hashed)
        if as_int >= n:
            raise RuntimeError(f'Key must be larger than {len(hashed) * 4}-bit')
        signature = pow(as_int, d, n)
        return Message.from_int(signature)

    def verify(self, signature, key):
        e, n = key
        hashed_message = pow(signature.int(), e, n)
        return self.hash() == int_to_hex(hashed_message)
