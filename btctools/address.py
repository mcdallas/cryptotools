import hashlib
from time import time
from datetime import timedelta

from btctools import base58
from ECDS.secp256k1 import generate_keypair
from transformations import int_to_hex, bytes_to_hex

"""Use http://gobittest.appspot.com/Address to make sure that you are producing the correct addresses"""


sha256 = lambda x: hashlib.sha256(x).digest()
ripemd160 = lambda x: hashlib.new('ripemd160', x).digest()

versions = {'P2PKH': b'\x00', 'P2SH': b'\x05', 'BIP32': b'\x04\x88\xb2\x1e'}


def pubkey_to_address(pub, version='P2PKH'):
    version_byte = versions[version.upper()]
    hashed = ripemd160(sha256(pub))
    payload = version_byte + hashed
    checksum = sha256(sha256(payload))[:4]
    address = payload + checksum
    return base58.encode(address)


def vanity(prefix):
    """Generate a vanity address starting with the input (excluding the version byte)"""
    not_in_alphabet = {i for i in prefix if i not in base58.ALPHABET}
    assert not not_in_alphabet, f"Characters {not_in_alphabet} are not in alphabet"
    start = time()
    counter = 0
    while True:
        counter += 1
        private, public = generate_keypair()
        address = pubkey_to_address(public)
        if address[1:].startswith(prefix):
            duration = timedelta(seconds=round(time() - start))
            print(f"Found address starting with {prefix} in {duration} after {counter:,} tries")
            return int_to_hex(private), bytes_to_hex(public), address
