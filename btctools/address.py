import hashlib
import base58

from ECDS.secp256k1 import generate_keypair
from transformations import bytes_to_hex

sha256 = lambda x: hashlib.sha256(x).digest()
hash160 = lambda x: hashlib.new('ripemd160', x).digest()

versions = {'P2PKH': b'\x00', 'P2SH': b'\x05', 'BIP32': b'\x04\x88\xb2\x1e'}


def pubkey_to_address(pub, version='P2PKH'):
    version_bytes = versions[version.upper()]
    hashed = hash160(sha256(pub))
    payload = version_bytes + hashed
    checksum = sha256(sha256(payload))[:4]
    address = payload + checksum
    return base58.encode(address)


def vanity(prefix):
    counter = 0
    not_in_alphabet = {i for i in prefix if i not in base58.ALPHABET}
    assert not not_in_alphabet, f"Characters {not_in_alphabet} are not in alphabet"
    while True:
        counter += 1
        private, public = generate_keypair()
        address = pubkey_to_address(public)
        if address[1:].startswith(prefix):
            print(f"Found address starting with {prefix} after {counter:,} tries")
            return bytes_to_hex(private), bytes_to_hex(public), address
