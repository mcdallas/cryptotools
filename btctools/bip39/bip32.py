import hmac
import hashlib
from typing import Union

from btctools import base58
from ECDSA.secp256k1 import CURVE, PrivateKey, PublicKey
from transformations import int_to_bytes, bytes_to_int, hash160
from btctools.network import network


"""https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-functions"""

KEY = Union[PrivateKey, PublicKey]


class KeyDerivationError(Exception):
    pass


class ExtendedKey:

    def __init__(self, key: KEY, code: bytes, depth=0, i=None):
        self.key = key
        self.code = code
        assert depth in range(256), 'Depth can only be 0-255'
        self.depth = depth
        if i is not None:
            assert 0 < i < 1 << 32, 'Invalid i'
        self.i = i

    def child(self, i):
        raise NotImplementedError

    def __div__(self, other):
        if isinstance(other, float):
            # hardened child derivation
            i = int(other) + 2**31
        elif isinstance(other, int):
            # non-hardened child derivation
            i = other
        else:
            raise TypeError
        return self.child(i)

    def id(self):
        raise NotImplementedError

    def fingerprint(self):
        return self.id()[:4]

    def serialize(self):
        raise NotImplementedError

    def encode(self):
        return base58.encode(self.serialize())


class Xprv(ExtendedKey):

    def child(self, i: int) -> 'Xprv':
        hardened = i >= 1 << 31

        if hardened:
            I = hmac.new(key=self.code, msg=self.keydata() + int_to_bytes(i).rjust(32, b'\x00'), digestmod=hashlib.sha512).digest()
        else:
            I = hmac.new(key=self.code, msg=self.key.to_public().encode(compressed=True) + int_to_bytes(i).rjust(32, b'\x00'), digestmod=hashlib.sha512).digest()

        I_L, I_R = bytes_to_int(I[:32]), I[32:]
        key = I_L + self.key.int() % CURVE.N
        if I_L >= CURVE.N or key == 0:
            return self.child(i+1)
        ret_code = I_R
        return Xprv(key, ret_code, depth=self.depth + 1, i=i)

    def to_xpub(self) -> 'Xpub':
        return Xpub(self.key.to_public(), self.code, depth=self.depth, i=self.i)

    def to_child_xpub(self, i: int) -> 'Xpub':
        # return self.child(i).to_xpub()  # works always
        return self.to_xpub().child(i)  # works only for non-hardened child keys

    def id(self):
        return hash160(self.key.to_public().encode(compressed=True))

    def keydata(self):
        return self.key.bytes().rjust(33, b'\x00')

    def serialize(self):
        version = network('xprv')
        depth = int_to_bytes(self.depth)
        fingerprint = bytes(4) if self.depth == 0 else self.fingerprint()
        child = bytes(4) if self.i is None else int_to_bytes(self.i).rjust(4, b'\x00')
        return version + depth + fingerprint + child + self.code + self.keydata()


class Xpub(ExtendedKey):

    def child(self, i: int) -> 'Xpub':
        hardened = i >= 1 << 31

        if hardened:
            raise KeyDerivationError('Cannot derive a hardened key from a Public key')

        I = hmac.new(key=self.code, msg=self.keydata() + int_to_bytes(i).rjust(32, b'\x00'))

        I_L, I_R = I[:32], I[32:]

        key = PrivateKey(I_L).to_public().point + self.key.point
        ret_code = I_R

        # TODO add point at infinity check
        return Xpub(key, ret_code, depth=self.depth + 1, i=i)

    def id(self):
        return hash160(self.key.encode(compressed=True))

    def keydata(self):
        return self.key.encode(compressed=True)

    def serialize(self):
        version = network('xpub')
        depth = int_to_bytes(self.depth)
        fingerprint = bytes(4) if self.depth == 0 else self.fingerprint()
        child = bytes(4) if self.i is None else int_to_bytes(self.i).rjust(4, b'\x00')
        return version + depth + fingerprint + child + self.code + self.keydata()
