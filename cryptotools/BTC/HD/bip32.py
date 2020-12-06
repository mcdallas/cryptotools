"""
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-functions
"""

import hmac
import hashlib
from typing import Union

from cryptotools.ECDSA.secp256k1 import CURVE, PrivateKey, PublicKey
from cryptotools.BTC import base58
from cryptotools.BTC.HD import to_seed
from cryptotools.BTC.address import ADDRESS
from cryptotools.BTC.network import network
from cryptotools.transformations import (
    bytes_to_hex,
    bytes_to_int,
    hash160,
    hex_to_bytes,
    int_to_bytes,
    sha256,
)

KEY = Union[PrivateKey, PublicKey]


class KeyDerivationError(Exception):
    pass


class ExtendedKey:
    root_path = NotImplemented

    def __init__(self, key: KEY, code: bytes, depth=0, i=None, parent=b'\x00\x00\x00\x00', path=None, addresstype='P2PKH'):
        self.key = key
        self.code = code
        assert depth in range(256), 'Depth can only be 0-255'
        self.depth = depth
        if i is not None:
            assert 0 <= i < 1 << 32, f'Invalid i : {i}'
        self.i = i
        self.parent = parent
        self.path = path or self.root_path
        assert (self.depth == 0 and self.i is None and self.parent == b'\x00\x00\x00\x00' and self.path == self.root_path) or \
               (self.depth != 0 and self.i is not None and self.parent != b'\x00\x00\x00\x00' and self.path != self.root_path), \
            f"Unable to determine if root path (depth={self.depth}, i={self.i}, path={self.path}, parent={bytes_to_hex(self.parent)})"

        self.type = ADDRESS(addresstype)

    def child(self, i):
        raise NotImplementedError

    def is_master(self):
        return self.depth == 0 and self.i is None and self.parent == b'\x00\x00\x00\x00' and self.path == self.root_path

    def __truediv__(self, other):
        if isinstance(other, float):
            # hardened child derivation
            i = int(other) + 2**31
        elif isinstance(other, int):
            # non-hardened child derivation
            i = other
        else:
            raise TypeError
        return self.child(i)

    def __floordiv__(self, other):
        if not isinstance(other, int):
            raise TypeError
        return self.child(other + 2**31)

    def id(self):
        raise NotImplementedError

    def fingerprint(self):
        return self.id()[:4]

    def serialize(self):
        raise NotImplementedError

    def encode(self):
        data = self.serialize()
        assert len(data) == 78
        checksum = sha256(sha256(data))[:4]
        return base58.encode(data + checksum)

    @classmethod
    def deserialize(cls, bts: bytes) -> 'ExtendedKey':

        def read(n):
            nonlocal bts
            data, bts = bts[:n], bts[n:]
            return data

        net = read(4)
        is_private = net in network('extended_prv').values()
        is_public = net in network('extended_pub').values()
        assert is_public ^ is_private, f'Invalid network bytes : {bytes_to_hex(net)}'
        address_lookup = {val: key for key, val in (network('extended_prv') if is_private else network('extended_pub')).items()}
        constructor = Xprv if is_private else Xpub
        depth = bytes_to_int(read(1))
        assert depth in range(256), f'Invalid depth : {depth}'
        fingerprint = read(4)
        i = bytes_to_int(read(4))
        if depth == 0:
            i = None
            path = None
        else:
            ih = f'{i}' if i < 2**31 else f"{i - 2**31}h"
            path = '/'.join([constructor.root_path] + ['x' for _ in range(depth - 1)] + [ih])

        code = read(32)
        key = read(33)
        key = PrivateKey(key) if is_private else PublicKey.decode(key)
        assert not bts, 'Leftover bytes'
        return constructor(key, code, depth=depth, i=i, parent=fingerprint, path=path, addresstype=address_lookup[net])

    @classmethod
    def decode(cls, string: str) -> 'ExtendedKey':
        bts = base58.decode(string)
        assert len(bts) == 82, f'Invalid length {len(bts)})'
        data, checksum = bts[:78], bts[78:]
        assert sha256(sha256(data)).startswith(checksum), 'Invalid checksum'
        return cls.deserialize(data)

    def __eq__(self, other):
        return self.encode() == other.encode()


class Xprv(ExtendedKey):
    root_path = 'm'

    def child(self, i: int) -> 'Xprv':
        hardened = i >= 1 << 31

        if hardened:
            I = hmac.new(key=self.code, msg=self.keydata() + int_to_bytes(i).rjust(4, b'\x00'), digestmod=hashlib.sha512).digest()
        else:
            I = hmac.new(key=self.code, msg=self.key.to_public().encode(compressed=True) + int_to_bytes(i).rjust(4, b'\x00'), digestmod=hashlib.sha512).digest()

        I_L, I_R = bytes_to_int(I[:32]), I[32:]
        key = (I_L + self.key.int()) % CURVE.N
        if I_L >= CURVE.N or key == 0:
            return self.child(i+1)
        ret_code = I_R
        if hardened:
            path = self.path + f'/{i - 2**31}h'
        else:
            path = self.path + f'/{i}'
        return Xprv(PrivateKey.from_int(key), ret_code, depth=self.depth + 1, i=i, parent=self.fingerprint(), path=path, addresstype=self.type.value)

    def to_xpub(self) -> 'Xpub':
        return Xpub(self.key.to_public(), self.code, depth=self.depth, i=self.i, parent=self.parent, path=self.path.replace('m', 'M'), addresstype=self.type.value)

    def to_child_xpub(self, i: int) -> 'Xpub':
        # return self.child(i).to_xpub()  # works always
        return self.to_xpub().child(i)  # works only for non-hardened child keys

    def id(self):
        return hash160(self.key.to_public().encode(compressed=True))

    def keydata(self):
        return self.key.bytes().rjust(33, b'\x00')

    def serialize(self):
        version = network('extended_prv')[self.type]
        depth = int_to_bytes(self.depth)
        child = bytes(4) if self.is_master() else int_to_bytes(self.i).rjust(4, b'\x00')
        return version + depth + self.parent + child + self.code + self.keydata()

    @classmethod
    def from_seed(cls, seed: Union[bytes, str], addresstype='P2PKH') -> 'Xprv':
        if isinstance(seed, str):
            seed = hex_to_bytes(seed)
        assert 16 <= len(seed) <= 64, 'Seed should be between 128 and 512 bits'
        I = hmac.new(key=b"Bitcoin seed", msg=seed, digestmod=hashlib.sha512).digest()
        I_L, I_R = I[:32], I[32:]
        if bytes_to_int(I_L) == 0 or bytes_to_int(I_L) > CURVE.N:
            raise KeyDerivationError
        key, code = PrivateKey(I_L), I_R
        return cls(key, code, addresstype=addresstype)

    def __repr__(self):
        return f"{self.__class__.__name__}(path={self.path}, key={self.key.wif(compressed=True)})"

    @classmethod
    def from_mnemonic(cls, mnemonic: str, passphrase='', addresstype='P2PKH') -> 'Xprv':
        seed = to_seed(mnemonic=mnemonic, passphrase=passphrase)
        return cls.from_seed(seed, addresstype=addresstype)

    def address(self, addresstype=None):
        return self.key.to_public().to_address(addresstype or self.type.value, compressed=True)


class Xpub(ExtendedKey):
    root_path = 'M'

    def child(self, i: int) -> 'Xpub':
        hardened = i >= 1 << 31

        if hardened:
            raise KeyDerivationError('Cannot derive a hardened key from an extended public key')

        I = hmac.new(key=self.code, msg=self.keydata() + int_to_bytes(i).rjust(4, b'\x00'), digestmod=hashlib.sha512).digest()

        I_L, I_R = I[:32], I[32:]

        key = PrivateKey(I_L).to_public().point + self.key.point
        ret_code = I_R
        path = self.path + f'/{i}'

        # TODO add point at infinity check
        return Xpub(PublicKey(key), ret_code, depth=self.depth + 1, i=i, parent=self.fingerprint(), path=path, addresstype=self.type.value)

    def id(self):
        return hash160(self.key.encode(compressed=True))

    def keydata(self):
        return self.key.encode(compressed=True)

    def serialize(self):
        version = network('extended_pub')[self.type]
        depth = int_to_bytes(self.depth)
        child = bytes(4) if self.is_master() else int_to_bytes(self.i).rjust(4, b'\x00')
        return version + depth + self.parent + child + self.code + self.keydata()

    def __repr__(self):
        return f"{self.__class__.__name__}(path={self.path}, key={self.key.hex(compressed=True)})"

    def address(self, addresstype=None):
        return self.key.to_address(addresstype or self.type.value, compressed=True)
