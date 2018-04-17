from transformations import bytes_to_int, int_to_bytes

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BASE = len(ALPHABET)


class Base58DecodeError(Exception):
    pass


def encode(bts: bytes) -> str:
    n = bytes_to_int(bts)
    leading_zero_bytes = len(bts) - len(bts.lstrip(b'\x00'))
    int_digits = []
    while n:
        int_digits.append(int(n % BASE))
        n //= BASE
    for _ in range(leading_zero_bytes):
        int_digits.append(0)
    return ''.join(ALPHABET[i] for i in reversed(int_digits))


def decode(b58: str) -> bytes:
    partial_sum = 0
    exponent = 0
    for digit in reversed(b58):
        try:
            partial_sum += ALPHABET.index(digit) * BASE**exponent
        except ValueError:
            raise DecodingError('Bad Byte') from None
        exponent += 1
    return int_to_bytes(partial_sum)
