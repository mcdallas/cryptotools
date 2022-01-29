import secrets
from typing import Union
from collections import deque

from cryptotools import message
from cryptotools import ECDSA
from cryptotools.number_theory_stuff import mulinv, modsqrt
from cryptotools.transformations import int_to_bytes, bytes_to_int, hex_to_int, bytes_to_hex, hex_to_bytes, hashtag, bytewise_xor, int_to_hex

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# Generator
G = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

CURVE = ECDSA.Curve(P, 0, 7, G, N, name='secp256k1')

class Point(ECDSA.AbstractPoint):
    # curve = CURVE

    def __init__(self, x, y):
        super().__init__(x, y, CURVE)

    def compact(self):
        return int_to_bytes(self.x).rjust(32, b'\x00')

    @classmethod
    def from_compact(cls, bts: bytes):
        assert len(bts) == 32, 'A compact Elliptic Curve Point representation is 32 bytes'
        x = bytes_to_int(bts)

        assert 0 < x < CURVE.P, "x not in 0..P-1"
        ysq = CURVE.f(x)
        y = pow(ysq, (CURVE.P + 1) // 4, CURVE.P)
        assert pow(y, 2, CURVE.P) == ysq

        return cls(x, y if y & 1 == 0 else CURVE.P - y)    

CURVE.Point = Point

class PrivateKey(message.Message):

    def __init__(self, bts):
        assert bytes_to_int(bts) < N, 'Key larger than Curve Order'
        super().__init__(bts)

    @classmethod
    def random(cls):
        key = secrets.randbelow(N)
        return cls.from_int(key)

    @classmethod
    def from_wif(cls, wif: str) -> 'PrivateKey':
        from cryptotools.BTC import base58, sha256
        from cryptotools.BTC.network import network
        bts = base58.decode(wif)
        network_byte, key, checksum = bts[0:1], bts[1:-4], bts[-4:]
        assert sha256(sha256(network_byte + key))[:4] == checksum, 'Invalid Checksum'
        assert network_byte == network('wif'), 'Invalid Network byte'
        if key.endswith(b'\x01'):
            key = key[:-1]
            compressed = True  # TODO
        else:
            compressed = False  # TODO
        return cls(key)

    def wif(self, compressed=False) -> str:
        from cryptotools.BTC import base58, sha256
        from cryptotools.BTC.network import network
        extended = network('wif') + self.bytes() + (b'\x01' if compressed else b'')
        hashed = sha256(sha256(extended))
        checksum = hashed[:4]
        return base58.encode(extended + checksum)

    def to_public(self) -> 'PublicKey':
        point = CURVE.G * self.int()
        return PublicKey(point)

    def __repr__(self):
        return f"PrivateKey({self.msg})"

    def sign_hash(self, hash):
        e = hex_to_int(hash) if isinstance(hash, str) else bytes_to_int(hash)
        r, s = 0, 0
        while r == 0 or s == 0:
            k = secrets.randbelow(N)
            point = CURVE.G * k
            r = point.x % N

            inv_k = mulinv(k, N)
            s = (inv_k * (e + r * self.int())) % N

        return Signature(r=r, s=s)


class PublicKey:

    def __init__(self, point: Point):
        self.point = point

    def __eq__(self, other: 'PublicKey') -> bool:
        return self.point == other.point

    def __repr__(self) -> str:
        return f"PublicKey({self.x}, {self.y})"

    @classmethod
    def decode(cls, key: bytes) -> 'PublicKey':
        if len(key) == 32:                 # compact key with implicit y coordinate
            key = b'\x02' + key
        if key.startswith(b'\x04'):        # uncompressed key
            assert len(key) == 65, 'An uncompressed public key must be 65 bytes long'
            x, y = bytes_to_int(key[1:33]), bytes_to_int(key[33:])
        else:                              # compressed key
            assert len(key) == 33, 'A compressed public key must be 33 bytes long'
            x = bytes_to_int(key[1:])
            root = modsqrt(CURVE.f(x), P)
            if key.startswith(b'\x03'):    # odd root
                y = root if root % 2 == 1 else -root % P
            elif key.startswith(b'\x02'):  # even root
                y = root if root % 2 == 0 else -root % P
            else:
                assert False, 'Wrong key format'
        return cls(Point(x, y))

    @classmethod
    def from_private(cls, prv):
        key = PrivateKey.from_int(prv) if isinstance(prv, int) else prv
        return key.to_public()

    @classmethod
    def from_hex(cls, hexstring: str) -> 'PublicKey':
        return cls.decode(hex_to_bytes(hexstring))

    @property
    def x(self) -> int:
        """X coordinate of the (X, Y) point"""
        return self.point.x

    @property
    def y(self) -> int:
        """Y coordinate of the (X, Y) point"""
        return self.point.y

    def encode(self, compressed=False, compact=False) -> bytes:
        if compact:
            return int_to_bytes(self.x).rjust(32, b'\x00')
        if compressed:
            if self.y & 1:  # odd root
                return b'\x03' + int_to_bytes(self.x).rjust(32, b'\x00')
            else:           # even root
                return b'\x02' + int_to_bytes(self.x).rjust(32, b'\x00')
        return b'\x04' + int_to_bytes(self.x).rjust(32, b'\x00') + int_to_bytes(self.y).rjust(32, b'\x00')

    def hex(self, compressed=False, compact=False) -> str:
        return bytes_to_hex(self.encode(compressed=compressed, compact=compact))

    def to_address(self, addrtype: str, compressed=False) -> str:
        from cryptotools.BTC.address import pubkey_to_address
        if compressed is True and addrtype == 'P2PKH':
            return pubkey_to_address(self.encode(compressed=True), addrtype)
        return pubkey_to_address(self, addrtype)


def is_pubkey(hexstr):
    try:
        if isinstance(hexstr, bytes):
            PublicKey.decode(hexstr)
        else:
            PublicKey.from_hex(hexstr)
    except AssertionError:
        return False
    return True


def generate_keypair():
    private = PrivateKey.random()
    public = private.to_public()
    return private, public

def has_even_y(point: Point) -> bool:
    return point.y & 1 == 0


class Signature:

    def __init__(self, r, s, force_low_s=True):
        self.r = r

        if force_low_s:
            # https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures
            self.s = s if s <=CURVE.N // 2 else CURVE.N - s
        else:
            self.s = s

    @classmethod
    def decode(cls, bts):
        
        data = deque(bts)
        lead = data.popleft() == 0x30
        assert lead, f'Invalid leading byte: 0x{lead:x}'  # ASN1 SEQUENCE
        sequence_length = data.popleft()
        assert sequence_length <= 70, f'Invalid Sequence length: {sequence_length}'
        lead = data.popleft()
        assert lead == 0x02, f'Invalid r leading byte: 0x{lead:x}'  # 0x02 byte before r
        len_r = data.popleft()
        assert len_r <= 33, f'Invalid r length: {len_r}'
        bts = bytes(data)
        r, data = bytes_to_int(bts[:len_r]), deque(bts[len_r:])
        lead = data.popleft()
        assert lead == 0x02, f'Invalid s leading byte: 0x{lead:x}'  # 0x02 byte before s
        len_s = data.popleft()
        assert len_s <= 33, f'Invalid s length: {len_s}'
        bts = bytes(data)
        s, rest = bytes_to_int(bts[:len_s]), bts[len_s:]
        assert len(rest) == 0, f'{len(rest)} leftover bytes'

        return cls(r, s)

    def encode(self):
        """https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#der-encoding"""
        r = int_to_bytes(self.r)
        if r[0] > 0x7f:
            r = b'\x00' + r
        s = int_to_bytes(self.s)

        if s[0] > 0x7f:
            s = b'\x00' + s

        len_r = int_to_bytes(len(r))
        len_s = int_to_bytes(len(s))
        len_sig = int_to_bytes(len(r) + len(s) + 4)
        return b'\x30' + len_sig + b'\x02' + len_r + r + b'\x02' + len_s + s

    def verify_hash(self, hash, pubkey):
        
        if not (1 <= self.r < CURVE.N and 1 <= self.s < CURVE.N):
            return False

        e = bytes_to_int(hash)
        w = mulinv(self.s, CURVE.N)
        u1 = (e * w) % CURVE.N
        u2 = (self.r * w) % CURVE.N

        point = CURVE.G * u1 + pubkey.point * u2
        return self.r % CURVE.N == point.x % CURVE.N

    @classmethod
    def from_hex(cls, hexstring):
        return cls.decode(hex_to_bytes(hexstring))

    def __repr__(self):
        return f"{self.__class__.__name__}({self.r}, {self.s})"

    def __eq__(self, other):
        return self.r == other.r and self.s == other.s

    def hex(self):
        return bytes_to_hex(self.encode())


class Schnorr:
    def __init__(self, R: 'Point', s: int):
        self.R = R
        self.s = s

    def encode(self):
        return self.R.compact() + int_to_bytes(self.s).rjust(32, b'\x00')

    def hex(self):
        return bytes_to_hex(self.encode())

    @classmethod
    def decode(cls, bts: bytes) -> 'Schnorr':
        assert len(bts) == 64, 'A Schnorr signature must be 64 bytes long'
        R = Point.from_compact(bts[:32])
        s = bytes_to_int(bts[32:])
        return cls(R, s)
        
    @classmethod
    def from_hex(cls, hex):
        return cls.decode(hex_to_bytes(hex))

def is_signature(hexstr):
    try:
        if isinstance(hexstr, bytes):
            Signature.decode(hexstr)
        else:
            Signature.from_hex(hexstr)
    except (AssertionError, IndexError, ValueError):
        return False
    return True

Sig = Union[Signature, Schnorr]


class Message(message.Message):

    def sign(self, private: PrivateKey) -> Signature:

        e = hex_to_int(self.hash())
        r, s = 0, 0
        while r == 0 or s == 0:
            k = secrets.randbelow(N)
            point = CURVE.G * k
            r = point.x % N

            inv_k = mulinv(k, N)
            s = (inv_k * (e + r * private.int())) % N

        return Signature(r=r, s=s)

    def sign_schnorr(self, private: PrivateKey, aux: bytes = None) -> Schnorr:
        """https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#default-signing"""
        
        if aux is None:
            aux = secrets.token_bytes(32)
        aux = aux.rjust(32, b'\x00')

        dprime = private.int()
        assert 0 < dprime < N, "Invalid private key"
        P = CURVE.G * dprime

        d = dprime if has_even_y(P) else CURVE.N - dprime

        t = bytewise_xor(int_to_bytes(d, 32), hashtag(b'BIP0340/aux', aux))

        rand = hashtag(tag=b'BIP0340/nonce', x=t + P.compact() + self.msg)
        kprime = bytes_to_int(rand) % CURVE.N
        assert kprime != 0, "Zero nonce"

        R = CURVE.G * kprime

        k = kprime if has_even_y(R) else CURVE.N - kprime

        e = hashtag(tag=b'BIP0340/challenge', x=R.compact() + P.compact() + self.msg)
        e = bytes_to_int(e) % CURVE.N

        s = (k + e*d) % CURVE.N

        return Schnorr(R, s)


    def _verify_schnorr(self, signature: Schnorr, public: PublicKey) -> bool:
        try:
            P = public.point
        except AssertionError:
            return False
        r = signature.R.x
        if r >= CURVE.P:
            return False

        if P.is_inf():
            return None

        s = signature.s
        if s >= CURVE.N:
            return False

        e = hashtag(tag=b'BIP0340/challenge', x=signature.R.compact() + P.compact() + self.msg)
        e = bytes_to_int(e) % CURVE.N

        R = CURVE.G * s - P * e
        if R.is_inf():
            return False
        if not has_even_y(R):
            return False
        if R.x != r:
            return False
        
        return True


    def verify(self, signature: Sig, public: PublicKey) -> bool:
        if isinstance(signature, Signature):
            return self._verify_ecdsa(signature, public)
        elif isinstance(signature, Schnorr):
            return self._verify_schnorr(signature, public)
        raise AssertionError("Unrecognized signature")

    def _verify_ecdsa(self, signature: Signature, public: PublicKey) -> bool:

        r, s = signature.r, signature.s
        if not (1 <= r < N and 1 <= s < N):
            return False

        e = hex_to_int(self.hash())
        w = mulinv(s, N)
        u1 = (e * w) % N
        u2 = (r * w) % N

        point = CURVE.G * u1 + public.point * u2
        return r % N == point.x % N



def verify_openssl(sig: Signature, sigform: bytes, pub: PublicKey):
    """Validate a signature using OpenSSL"""
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as dirname:
        with open(dirname + '/sig.raw', 'wb') as file:
            file.write(sig.encode())

        with open(dirname + '/hash1.sha256', 'wb') as file:
            file.write(sha256(sigform))

        with open(dirname + '/key.hex', 'w') as file:
            file.write('3056301006072a8648ce3d020106052b8104000a034200\n' + pub.hex())

        os.system(f'xxd -r -p < {dirname}/key.hex | openssl pkey -pubin -inform der > {dirname}/key.pem')
        os.system(f'openssl sha256 < {dirname}/hash1.sha256 -verify {dirname}/key.pem -signature {dirname}/sig.raw')