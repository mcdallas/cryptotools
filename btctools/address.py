import hashlib
from time import time
from datetime import timedelta
from functools import partial

from btctools import base58, bech32
from ECDS.secp256k1 import generate_keypair
from transformations import bytes_to_hex, int_to_bytes


sha256 = lambda x: hashlib.sha256(x).digest()
ripemd160 = lambda x: hashlib.new('ripemd160', x).digest()
hash160 = lambda x: ripemd160(sha256(x))

HRP = 'bc'


def legacy_address(pub_or_script, version_byte):
    """https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses"""
    hashed = hash160(pub_or_script)
    payload = int_to_bytes(version_byte) + hashed
    checksum = sha256(sha256(payload))[:4]
    address = payload + checksum
    return base58.encode(address)


def pubkey_to_p2wpkh(pub, version_byte, witver):
    """https://github.com/bitcoin/bips/blob/master/bip-0142.mediawiki#specification"""
    payload = int_to_bytes(version_byte) + int_to_bytes(witver) + b'\x00' + hash160(pub)
    checksum = sha256(sha256(payload))[:4]
    return base58.encode(payload + checksum)


def script_to_p2wsh(script, version_byte, witver):
    """https://github.com/bitcoin/bips/blob/master/bip-0142.mediawiki#specification"""
    payload = int_to_bytes(version_byte) + int_to_bytes(witver) + b'\x00' + sha256(script)
    checksum = sha256(sha256(payload))[:4]
    return base58.encode(payload + checksum)


def to_bech32(pubkey_or_script, witver):
    assert isinstance(pubkey_or_script, bytes)
    is_key = pubkey_or_script.startswith((b'\02', b'\03')) and len(pubkey_or_script) == 33
    return pubkey_to_bech32(pubkey_or_script, witver) if is_key else script_to_bech32(pubkey_or_script, witver)


def script_to_bech32(script, witver):
    """https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#witness-program"""
    witprog = sha256(script)
    return bech32.encode(HRP, witver, witprog)


def pubkey_to_bech32(pub, witver):
    """https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#witness-program"""
    witprog = hash160(pub)
    return bech32.encode(HRP, witver, witprog)


versions = {
    'P2PKH': partial(legacy_address, version_byte=0x00),
    'P2SH': partial(legacy_address, version_byte=0x05),
    'P2WPKH': partial(pubkey_to_p2wpkh, version_byte=0x06, witver=0x00),
    'P2WSH': partial(script_to_p2wsh, version_byte=0x0A, witver=0x00),
    'BECH32': partial(to_bech32, witver=0x00),
}


def pubkey_to_address(pub, version='P2PKH'):
    """Input is a public key for P2PKH/P2WPKH and a script for P2SH/P2wSH"""
    converter = versions[version.upper()]
    return converter(pub)


def op_push(i):
    """https://en.bitcoin.it/wiki/Script#Constants"""
    if i < 0x4c:
        return int_to_bytes(i)
    elif i < 0xff:
        return b'\x4c' + int_to_bytes(i)
    elif i < 0xffff:
        return b'\x4d' + int_to_bytes(i)
    else:
        return b'\x4e' + int_to_bytes(i)


def address_to_script(addr):
    """https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#segwit-address-format"""
    hrp, _ = bech32.bech32_decode(addr)
    if hrp not in ('bc', 'tb'):
        raise bech32.Bech32DecodeError('Invalid human-readable part')
    witver, witprog = bech32.decode(hrp, addr)
    if not (0 <= witver <= 16):
        raise bech32.Bech32DecodeError('Invalid witness version')

    OP_n = int_to_bytes(witver + 0x50 if witver > 0 else 0)
    script = OP_n + op_push(len(witprog)) + bytes(witprog)
    return script


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
            return bytes_to_hex(private), bytes_to_hex(public), address
