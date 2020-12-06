import unicodedata
import hashlib

from pathlib import Path
from bisect import bisect_left

from cryptotools.transformations import int_to_bin, bin_to_bytes, bytes_to_bin, sha256
from cryptotools.btctools.HD.pbkdf2 import pbkdf2_bin

HERE = Path(__file__).absolute().parent

with open(HERE / 'wordlist.txt') as file:
    WORDS = file.read().split('\n')


class InvalidMnemonic(Exception):
    pass


def binary_search(word):
    hi, lo = len(WORDS), 0
    pos = bisect_left(WORDS, word, lo, hi)  # find insertion position
    if pos != hi and WORDS[pos] == word:
        return pos
    raise LookupError(f'{word} not in list')


def check(mnemonic):
    mnemonic = mnemonic.lower().split()

    if len(mnemonic) not in {12, 15, 18, 21, 24}:
        return False

    try:
        indexes = [binary_search(word) for word in mnemonic]
    except LookupError:
        return False

    bits = ''.join(int_to_bin(idx).zfill(11) for idx in indexes)
    checksum_length = len(mnemonic)//3
    data, checksum = bin_to_bytes(bits[:-checksum_length]), bits[-checksum_length:]
    return bytes_to_bin(sha256(data)).zfill(256)[:checksum_length] == checksum


def normalize_string(txt):
    if isinstance(txt, bytes):
        utxt = txt.decode('utf8')
    elif isinstance(txt, str):  # noqa: F821
        utxt = txt
    else:
        raise TypeError("String value expected")

    return unicodedata.normalize('NFKD', utxt)


def to_seed(mnemonic, passphrase=''):
    mnemonic = normalize_string(mnemonic)
    passphrase = normalize_string(passphrase)
    if not check(mnemonic):
        raise InvalidMnemonic
    return pbkdf2_bin(mnemonic, 'mnemonic' + passphrase, iterations=2048, keylen=64, hashfunc=hashlib.sha512)
