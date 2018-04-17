from time import time
from datetime import timedelta
from functools import partial
from typing import Union, Tuple

from btctools import base58, bech32
from btctools.script import push, witness_byte
from btctools.opcodes import TX
from ECDS.secp256k1 import generate_keypair, PublicKey
from transformations import int_to_bytes, hash160, sha256

HRP = 'bc'


def legacy_address(pub_or_script: Union[bytes, PublicKey], version_byte: int) -> str:
    """https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses"""
    bts = pub_or_script.encode(compressed=False) if isinstance(pub_or_script, PublicKey) else pub_or_script
    hashed = hash160(bts)
    payload = int_to_bytes(version_byte) + hashed
    checksum = sha256(sha256(payload))[:4]
    address = payload + checksum
    return base58.encode(address)


## WAS REPLACED BY BIP 173
# def pubkey_to_p2wpkh(pub, version_byte, witver):
#     """https://github.com/bitcoin/bips/blob/master/bip-0142.mediawiki#specification"""
#     payload = int_to_bytes(version_byte) + int_to_bytes(witver) + b'\x00' + hash160(pub.encode(compressed=True))
#     checksum = sha256(sha256(payload))[:4]
#     return base58.encode(payload + checksum)


## WAS REPLACED WITH BIP 173
# def script_to_p2wsh(script, version_byte, witver):
#     """https://github.com/bitcoin/bips/blob/master/bip-0142.mediawiki#specification"""
#     payload = int_to_bytes(version_byte) + int_to_bytes(witver) + b'\x00' + sha256(script)
#     checksum = sha256(sha256(payload))[:4]
#     return base58.encode(payload + checksum)


def script_to_bech32(script: bytes, witver: int) -> str:
    """https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#witness-program"""
    witprog = sha256(script)
    return bech32.encode(HRP, witver, witprog)


def pubkey_to_bech32(pub: PublicKey, witver: int) -> str:
    """https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#witness-program"""
    witprog = hash160(pub.encode(compressed=True))
    return bech32.encode(HRP, witver, witprog)


key_to_addr_versions = {
    'P2PKH': partial(legacy_address, version_byte=0x00),
    # 'P2WPKH': partial(pubkey_to_p2wpkh, version_byte=0x06, witver=0x00),  # WAS REPLACED BY BIP 173
    'P2WPKH-P2SH': lambda pub: legacy_address(witness_byte(witver=0) + push(hash160(pub.encode(compressed=False))), version_byte=0x05),
    'P2WPKH': partial(pubkey_to_bech32, witver=0x00),
}

script_to_addr_versions = {
    'P2SH': partial(legacy_address, version_byte=0x05),
    # 'P2WSH': partial(script_to_p2wsh, version_byte=0x0A, witver=0x00),  # WAS REPLACED BY BIP 173
    'P2WSH-P2SH': lambda script: legacy_address(witness_byte(witver=0) + push(sha256(script)), version_byte=0x05),
    'P2WSH': partial(script_to_bech32, witver=0x00),
}


def pubkey_to_address(pub: PublicKey, version='P2PKH') -> str:
    converter = key_to_addr_versions[version.upper()]
    return converter(pub)


def script_to_address(script: bytes, version='P2SH') -> str:
    """Redeem script to address"""
    converter = script_to_addr_versions[version.upper()]
    return converter(script)


def address_to_script(addr: str) -> bytes:
    """https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#segwit-address-format"""
    hrp, _ = bech32.bech32_decode(addr)
    if hrp not in ('bc', 'tb'):
        raise bech32.Bech32DecodeError('Invalid human-readable part')
    witver, witprog = bech32.decode(hrp, addr)
    if not (0 <= witver <= 16):
        raise bech32.Bech32DecodeError('Invalid witness version')

    script = witness_byte(witver) + push(bytes(witprog))
    return script


class InvalidAddress(Exception):
    pass


def address_type(addr):
    if addr.startswith(('1', '3')):
        try:
            address = base58.decode(addr).rjust(25, b'\x00')
        except base58.Base58DecodeError as e:
            raise InvalidAddress(f"{addr} : {e}") from None
        payload, checksum = address[:-4], address[-4:]
        version_byte, digest = payload[0], payload[1:].rjust(20, b'\x00')
        if len(digest) != 20:
            raise InvalidAddress(f"{addr} : Bad Payload") from None
        if sha256(sha256(payload))[:4] != checksum:
            raise InvalidAddress(f"{addr} : Invalid checksum") from None
        try:
            return {0x00: TX.P2PKH, 0x05: TX.P2SH}[version_byte]
        except KeyError:
            raise InvalidAddress(f"{addr} : Invalid version byte") from None
    elif addr.startswith('bc1'):
        try:
            witness_version, witness_program = bech32.decode(HRP, addr)
        except bech32.Bech32DecodeError as e:
            raise InvalidAddress(f"{addr} : {e}") from None

        if not witness_version == 0x00:
            raise InvalidAddress(f"{addr} : Invalid witness version") from None
        if len(witness_program) == 20:
            return TX.P2WPKH
        elif len(witness_program) == 32:
            return TX.P2WSH
        else:
            raise InvalidAddress(f"{addr} : Invalid witness program") from None
    else:
        raise InvalidAddress(f"{addr} : Invalid leading character") from None


def vanity(prefix: str) -> Tuple[str, str, str]:
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
