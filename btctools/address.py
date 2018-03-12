import hashlib
from time import time
from datetime import timedelta
from functools import partial

from btctools import base58, bech32
from ECDS.secp256k1 import generate_keypair, PublicKey
from transformations import int_to_bytes


sha256 = lambda x: hashlib.sha256(x).digest()
ripemd160 = lambda x: hashlib.new('ripemd160', x).digest()
hash160 = lambda x: ripemd160(sha256(x))

HRP = 'bc'


def legacy_address(pub_or_script, version_byte):
    """https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses"""
    bts = pub_or_script.encode(compressed=False) if isinstance(pub_or_script, PublicKey) else pub_or_script
    hashed = hash160(bts)
    payload = int_to_bytes(version_byte) + hashed
    checksum = sha256(sha256(payload))[:4]
    address = payload + checksum
    return base58.encode(address)


def pubkey_to_p2wpkh(pub, version_byte, witver):
    """https://github.com/bitcoin/bips/blob/master/bip-0142.mediawiki#specification"""
    payload = int_to_bytes(version_byte) + int_to_bytes(witver) + b'\x00' + hash160(pub.encode(compressed=True))
    checksum = sha256(sha256(payload))[:4]
    return base58.encode(payload + checksum)


def script_to_p2wsh(script, version_byte, witver):
    """https://github.com/bitcoin/bips/blob/master/bip-0142.mediawiki#specification"""
    payload = int_to_bytes(version_byte) + int_to_bytes(witver) + b'\x00' + sha256(script)
    checksum = sha256(sha256(payload))[:4]
    return base58.encode(payload + checksum)


def script_to_bech32(script, witver):
    """https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#witness-program"""
    witprog = sha256(script)
    return bech32.encode(HRP, witver, witprog)


def pubkey_to_bech32(pub, witver):
    """https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#witness-program"""
    witprog = hash160(pub.encode(compressed=True))
    return bech32.encode(HRP, witver, witprog)


key_to_addr_versions = {
    'P2PKH': partial(legacy_address, version_byte=0x00),
    'P2WPKH': partial(pubkey_to_p2wpkh, version_byte=0x06, witver=0x00),
    'P2WPKH-P2SH': lambda pub: legacy_address(witness_byte(witver=0) + push_script(hash160(pub.encode(compressed=False))), version_byte=0x05),
    'BECH32': partial(pubkey_to_bech32, witver=0x00),
}

script_to_addr_versions = {
    'P2SH': partial(legacy_address, version_byte=0x05),
    'P2WSH': partial(script_to_p2wsh, version_byte=0x0A, witver=0x00),
    'P2WSH-P2SH': lambda script: legacy_address(witness_byte(witver=0) + push_script(sha256(script)), version_byte=0x05),
    'BECH32': partial(script_to_bech32, witver=0x00),
}


def pubkey_to_address(pub, version='P2PKH'):
    converter = key_to_addr_versions[version.upper()]
    return converter(pub)


def script_to_address(script, version='P2SH'):
    converter = script_to_addr_versions[version.upper()]
    return converter(script)


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


def push_script(script):
    return op_push(len(script)) + script


def witness_byte(witver):
    assert 0 <= witver <= 16, "Witness version must be between 0-16"
    return int_to_bytes(witver + 0x50 if witver > 0 else 0)


def address_to_script(addr):
    """https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#segwit-address-format"""
    hrp, _ = bech32.bech32_decode(addr)
    if hrp not in ('bc', 'tb'):
        raise bech32.Bech32DecodeError('Invalid human-readable part')
    witver, witprog = bech32.decode(hrp, addr)
    if not (0 <= witver <= 16):
        raise bech32.Bech32DecodeError('Invalid witness version')

    script = witness_byte(witver) + push_script(bytes(witprog))
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
            return private.hex(), public.hex(), address
