# Copyright (c) 2017 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Reference implementation for Bech32 and segwit addresses - tweaked to provide descriptive errors"""

from typing import Tuple, List

Bytes = List[int]


class Bech32DecodeError(Exception):
    pass


CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values: Bytes) -> int:
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str) -> Bytes:
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp: str, data: Bytes) -> bool:
    """Verify a checksum given HRP and converted data characters."""
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def bech32_create_checksum(hrp: str, data: Bytes) -> Bytes:
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: Bytes) -> str:
    """Compute a Bech32 string given HRP and data values."""
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])


def bech32_decode(bech: str) -> Tuple[str, Bytes]:
    """Validate a Bech32 string, and determine HRP and data."""
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        raise Bech32DecodeError('Character outside the US-ASCII [33-126] range')

    if (bech.lower() != bech) and (bech.upper() != bech):
        raise Bech32DecodeError('Mixed upper and lower case')

    bech = bech.lower()
    pos = bech.rfind('1')

    if pos == 0:
        raise Bech32DecodeError('Empty human readable part')
    elif pos == -1:
        raise Bech32DecodeError('No seperator character')
    elif pos + 7 > len(bech):
        raise Bech32DecodeError('Checksum too short')

    if len(bech) > 90:
        raise Bech32DecodeError('Max string length exceeded')

    if not all(x in CHARSET for x in bech[pos+1:]):
        raise Bech32DecodeError('Character not in charset')

    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos+1:]]

    if not bech32_verify_checksum(hrp, data):
        raise Bech32DecodeError('Invalid checksum')

    return hrp, data[:-6]


def convertbits(data: Bytes, frombits: int, tobits: int, pad=True) -> Bytes:
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise Bech32DecodeError
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise Bech32DecodeError
    return ret


def decode(hrp: str, addr: str) -> Tuple[int, Bytes]:
    """Decode a segwit address."""
    hrpgot, data = bech32_decode(addr)
    if hrpgot != hrp:
        raise Bech32DecodeError('Human readable part mismatch')

    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2:
        raise Bech32DecodeError('Witness programm too short')
    elif len(decoded) > 40:
        raise Bech32DecodeError('Witness programm too long')

    if data[0] > 16:
        raise Bech32DecodeError('Invalid witness version')

    if data[0] == 0 and (len(decoded) not in (20, 32)):
        raise Bech32DecodeError('Could not interpret witness programm')

    return data[0], decoded


def encode(hrp: str, witver: int, witprog: Bytes) -> str:
    """Encode a segwit address."""
    return bech32_encode(hrp, [witver] + convertbits(witprog, 8, 5))
