import hashlib
import base58

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

