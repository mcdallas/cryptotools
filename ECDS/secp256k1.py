import secrets
import message
from hashlib import sha256

import ECDS
from number_theory_stuff import mulinv, modsqrt
from transformations import int_to_bytes, bytes_to_int, hex_to_int

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


def encode_public_key(key: Point, compressed=False) -> bytes:
    if compressed:
        if key.y & 1:  # odd root
            return b'\x03' + int_to_bytes(key.x).zfill(32)
        else:  # even root
            return b'\x02' + int_to_bytes(key.x).zfill(32)
    return b'\x04' + int_to_bytes(key.x).zfill(32) + int_to_bytes(key.y).zfill(32)


def encode_private_key(key, compressed=False):
    from btctools import base58
    extended = b'\x80' + key + (b'\x01' if compressed else b'')
    hashed = sha256(sha256(extended).digest()).digest()
    checksum = hashed[:4]
    return base58.encode(extended + checksum)


def decode_private_key(wif):
    from btctools import base58
    bts = base58.decode(wif)
    bt80, key, checksum = bts[0:1], bts[1:-4], bts[-4:]
    assert sha256(sha256(bt80 + key).digest()).digest()[:4] == checksum, 'Invalid Checksum'
    assert bt80 == b'\x80', 'Invalid Format'
    if key.endswith(b'\x01'):
        key = key[:-1]
        compressed = True  # TODO
    else:
        compressed = False  # TODO
    return key


def decode_public_key(key: bytes) -> Point:
    if key.startswith(b'\x04'):  # uncompressed key
        assert len(key) == 65, 'Uncompressed key must be 65 bytes long'
        x, y = bytes_to_int(key[1:33]), bytes_to_int(key[33:])
    else:  # compressed key
        assert len(key) == 33, 'Compressed key must be 33 bytes long'
        x = bytes_to_int(key[1:])
        root = modsqrt(CURVE.f(x), P)
        if key.startswith(b'\x03'):  # odd root
            y = root if root % 2 == 1 else -root % P
        elif key.startswith(b'\x02'):  # even root
            y = root if root % 2 == 0 else -root % P
        else:
            assert False, 'Wrong key format'

    return Point(x, y)


def generate_keypair(encoded=True):
    private = secrets.randbelow(N)
    public = private_to_public(private)
    return (int_to_bytes(private), encode_public_key(public)) if encoded else (private, public)


class Message(message.Message):

    def sign(self, private):
        if isinstance(private, bytes):
            private = bytes_to_int(private)
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
        if isinstance(public, bytes):
            public = decode_public_key(public)

        r, s = signature
        if not (1 <= r < N and 1 <= s < N):
            return False

        e = hex_to_int(self.hash())
        w = mulinv(s, N)
        u1 = (e * w) % N
        u2 = (r * w) % N

        point = CURVE.G * u1 + public * u2
        return r % N == point.x % N

