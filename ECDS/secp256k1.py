
import secrets
import message
from transformations import int_to_bytes, hex_to_int
from RSA.rsa import mulinv
import ECDS

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# Generator
G = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

CURVE = ECDS.Curve(P, 0, 7, G, N, name='secp256k1')


class Point(ECDS.Point):

    def __init__(self, x, y):
        super().__init__(x, y, CURVE)


def private_to_public(key: int) -> Point:
    return CURVE.G * key


def encode_public_key(key: Point) -> bytes:
    return b'\x04' + int_to_bytes(key.x) + int_to_bytes(key.y)


def generate_keypair():
    private = secrets.randbelow(N)
    public = private_to_public(private)
    return int_to_bytes(private), encode_public_key(public)


class Message(message.Message):

    def sign(self, private):
        e = hex_to_int(self.hash())
        r, s = 0, 0
        while r == 0 or s == 0:
            k = secrets.randbelow(N)
            point = CURVE.G * k
            r = point.x % N

            inv_k = mulinv(k, N)
            s = (inv_k * (e + r * private)) % N

        return r, s

    def verify(self, signature, public):
        if isinstance(public, tuple):
            public = Point(*public)
        r, s = signature
        if not (1 <= r < N and 1 <= s < N):
            return False

        e = hex_to_int(self.hash())
        w = mulinv(s, N)
        u1 = (e * w) % N
        u2 = (r * w) % N

        point = CURVE.G * u1 + public * u2
        return r % N == point.x % N

