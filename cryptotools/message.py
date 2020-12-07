import base64
from hashlib import sha256 as hasher
from cryptotools.transformations import *


__all__ = ['Message', 'is_signature', 'verify_openssl']

class Message:
    """Basic data class with useful constructors and methods"""

    def __init__(self, bytes):
        self.msg = bytes

    @classmethod
    def from_int(cls, i):
        return cls(int_to_bytes(i))

    @classmethod
    def from_hex(cls, h):
        return cls(hex_to_bytes(h))

    @classmethod
    def from_str(cls, s, encoding='utf-8'):
        return cls(str.encode(s, encoding))

    @classmethod
    def from_binary(cls, b):
        return cls(int_to_bytes(int(b, 2)))

    @classmethod
    def from_base64(cls, s):
        return cls(base64.b64decode(s))

    @classmethod
    def from_file(cls, path):
        with open(path, 'rb') as f:
            b = f.read()
        return cls(b)

    def int(self):
        return bytes_to_int(self.msg)

    def str(self, encoding='utf-8'):
        return self.msg.decode(encoding)

    def hex(self):
        return bytes_to_hex(self.msg)

    def bin(self):
        return format(bytes_to_int(self.msg), 'b')

    def bytes(self):
        return self.msg

    def base64(self):
        return base64.b64encode(self.msg).decode()

    def __repr__(self):
        return repr(self.msg)

    def __eq__(self, other):
        return self.msg == other.msg

    def __len__(self):
        return len(self.bin())  # in bits

    def hash(self):
        return hasher(self.msg).hexdigest()


class Signature:

    def __init__(self, r, s, force_low_s=True):
        self.r = r

        if force_low_s:
            # https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures
            from cryptotools.ECDSA.secp256k1 import N
            self.s = s if s <= N // 2 else N - s
        else:
            self.s = s

    @classmethod
    def decode(cls, bts):
        from collections import deque
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
        from cryptotools.ECDSA.secp256k1 import N, mulinv, CURVE
        if not (1 <= self.r < N and 1 <= self.s < N):
            return False

        e = bytes_to_int(hash)
        w = mulinv(self.s, N)
        u1 = (e * w) % N
        u2 = (self.r * w) % N

        point = CURVE.G * u1 + pubkey.point * u2
        return self.r % N == point.x % N

    @classmethod
    def from_hex(cls, hexstring):
        return cls.decode(hex_to_bytes(hexstring))

    def __repr__(self):
        return f"{self.__class__.__name__}({self.r}, {self.s})"

    def __eq__(self, other):
        return self.r == other.r and self.s == other.s

    def hex(self):
        return bytes_to_hex(self.encode())


def is_signature(hexstr):
    try:
        if isinstance(hexstr, bytes):
            Signature.decode(hexstr)
        else:
            Signature.from_hex(hexstr)
    except (AssertionError, IndexError):
        return False
    return True


def verify_openssl(sig: Signature, sigform: bytes, pub: 'PublicKey'):
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
