import base64
from hashlib import sha256 as hasher
from cryptotools.transformations import *


__all__ = []

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
