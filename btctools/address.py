from time import time
from datetime import timedelta
from functools import partial
from typing import Union, Tuple

from btctools import base58, bech32
from btctools.script import push, witness_byte, get_type, witness_program, version_byte
from btctools.opcodes import TX, OP, ADDRESS
from btctools.network import network, networks
from btctools.transaction import Output, Transaction
from btctools.error import ValidationError, InvalidAddress, Bech32DecodeError, Base58DecodeError, UpstreamError, HTTPError
from ECDSA.secp256k1 import generate_keypair, PublicKey, PrivateKey
from transformations import hex_to_bytes, bytes_to_hex, bytes_to_int, hash160, sha256, btc_to_satoshi


def legacy_address(pub_or_script: Union[bytes, PublicKey], version_byte: bytes) -> str:
    """https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses"""
    bts = pub_or_script.encode(compressed=False) if isinstance(pub_or_script, PublicKey) else pub_or_script
    hashed = hash160(bts)
    payload = version_byte + hashed
    return hashed_payload_to_address(payload)


def hashed_payload_to_address(payload):
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


def script_to_bech32(script: bytes, witver: int, _network=None) -> str:
    """https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#witness-program"""
    witprog = sha256(script)
    return bech32.encode(network('hrp', _network), witver, witprog)


def pubkey_to_bech32(pub: PublicKey, witver: int) -> str:
    """https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#witness-program"""
    witprog = hash160(pub.encode(compressed=True))
    return bech32.encode(network('hrp', pub.network()), witver, witprog)


key_to_addr_versions = {
    ADDRESS.P2PKH: lambda pub: legacy_address(pub, version_byte=network('keyhash', pub.network())),
    # 'P2WPKH': partial(pubkey_to_p2wpkh, version_byte=0x06, witver=0x00),  # WAS REPLACED BY BIP 173
    ADDRESS.P2WPKH_P2SH: lambda pub: legacy_address(witness_byte(witver=0) + push(hash160(pub.encode(compressed=True))), version_byte=network('scripthash', pub.network())),
    ADDRESS.P2WPKH: lambda pub: pubkey_to_bech32(pub, witver=0x00),
}

script_to_addr_versions = {
    ADDRESS.P2SH: lambda script, _network=None: legacy_address(script, version_byte=network('scripthash', _network)),
    # 'P2WSH': partial(script_to_p2wsh, version_byte=0x0A, witver=0x00),  # WAS REPLACED BY BIP 173
    ADDRESS.P2WSH_P2SH: lambda script, _network=None: legacy_address(witness_byte(witver=0) + push(sha256(script)), version_byte=network('scripthash', _network)),
    ADDRESS.P2WSH: lambda script, _network=None: script_to_bech32(script, witver=0x00, _network=_network),
}


def pubkey_to_address(pub: PublicKey, version='P2PKH') -> str:
    converter = key_to_addr_versions[ADDRESS(version.upper())]
    return converter(pub)


def script_to_address(script: bytes, version='P2SH', _network=None) -> str:
    """Redeem script to address"""
    converter = script_to_addr_versions[ADDRESS(version.upper())]
    return converter(script, _network)


def address_to_script(addr: str) -> bytes:
    """https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#segwit-address-format"""
    hrp, _ = bech32.bech32_decode(addr)
    if hrp not in [net['hrp'] for net in networks.values()]:
        raise Bech32DecodeError('Invalid human-readable part')
    witver, witprog = bech32.decode(hrp, addr)
    if not (0 <= witver <= 16):
        raise Bech32DecodeError('Invalid witness version')

    script = witness_byte(witver) + push(bytes(witprog))
    return script


def get_address(script, _network=None):
    """Extracts the address from a scriptPubkey"""
    script = hex_to_bytes(script) if isinstance(script, str) else script
    stype = get_type(script)
    if stype == TX.P2SH:
        data = script[2:22]
        version = network('scripthash', _network)
        return hashed_payload_to_address(version + data)
    elif stype == TX.P2PKH:
        data = script[3:23]
        version = network('keyhash', _network)
        return hashed_payload_to_address(version + data)
    elif stype in (TX.P2WSH, TX.P2WPKH):
        witver = version_byte(script)
        witprog = witness_program(script)
        return bech32.encode(network('hrp', _network), witver, witprog)
    elif stype == TX.P2PK:
        return "N/A"
    raise ValidationError(f"Unknown script type: {bytes_to_hex(script)}")


class Address:
    _network = None

    def __init__(self, address, _network=None):
        self.address = address
        self._outputs = None
        self._network = _network

    @property
    def utxos(self):
        if self._outputs is None:
            import urllib.request
            import json
            url = network('utxo_url', self._network).format(address=self.address)

            req = urllib.request.Request(url)
            outputs = []
            try:
                with urllib.request.urlopen(req) as resp:
                    data = json.loads(resp.read().decode())
            except HTTPError as e:
                resp = e.read().decode()
                if resp == 'No free outputs to spend':
                    self._outputs = []
                else:
                    raise UpstreamError(resp)
            else:
                for item in data['unspent_outputs']:
                    out = Output(value=item['value'], script=hex_to_bytes(item['script']))
                    out.parent_id = hex_to_bytes(item['tx_hash_big_endian'])
                    out.tx_index = item['tx_output_n']
                    outputs.append(out)
                self._outputs = outputs
        return self._outputs

    def type(self):
        return address_type(self.address)

    def balance(self):
        self._outputs = None  # Force refresh
        return sum((out.value for out in self.utxos))/10**8

    def __repr__(self):
        return f"Address({self.address}, type={self.type().value}, balance={self.balance()} BTC)" \
            if self._outputs else f"Address({self.address}, type={self.type().value})"

    def send(self, to: dict, fee: float, private: PrivateKey) -> Transaction:
        balance = btc_to_satoshi(self.balance())
        fee = btc_to_satoshi(fee)
        to = {key: btc_to_satoshi(val) for key, val in to.items()}
        sum_send = sum(to.values())
        if balance < sum_send + fee:
            raise ValidationError("Insufficient balance")
        elif balance > sum_send + fee:
            raise ValidationError(f"You are trying to send {sum_send/10**8} BTC which is "
                                  f"less than this address' current balance of {balance/10**8}."
                                  f" You must provide a change address or explicitly add the difference as a fee")
        inputs = [out.spend() for out in self.utxos]
        outputs = [Address(addr)._receive(val) for addr, val in to.items()]
        tx = Transaction(inputs=inputs, outputs=outputs)
        for idx in range(len(tx.inputs)):
            tx.inputs[idx].tx_index = idx
            tx.inputs[idx]._parent = tx
        for inp in tx.inputs:
            inp.sign(private)
        return tx

    def _receive(self, value: int):
        """Creates an output that sends to this address"""
        addr_type = self.type()
        output = Output(value=value, script=b'')
        if addr_type == ADDRESS.P2PKH:
            address = base58.decode(self.address).rjust(25, b'\x00')
            keyhash = address[1:-4]
            output.script = OP.DUP.byte + OP.HASH160.byte + push(keyhash) + OP.EQUALVERIFY.byte + OP.CHECKSIG.byte
        elif addr_type == ADDRESS.P2SH:
            address = base58.decode(self.address).rjust(25, b'\x00')
            scripthash = address[1:-4]
            output.script = OP.HASH160.byte + push(scripthash) + OP.EQUAL.byte
        elif addr_type in (ADDRESS.P2WPKH, ADDRESS.P2WSH):
            witness_version, witness_program = bech32.decode(network('hrp', self._network), self.address)
            output.script = OP(bytes_to_int(witness_byte(witness_version))).byte + push(bytes(witness_program))
        else:
            raise ValidationError(f"Cannot create output of type {addr_type}")
        return output


def send(source, to, fee, private):
    addr = Address(source)
    prv_to_addr = private.to_public().to_address(addr.type().value)
    assert source == prv_to_addr, 'This private key does not correspond to the given address'
    tx = addr.send(to=to, fee=fee, private=private)
    assert tx.verify(), 'Something went wrong, could not verify signed transaction'
    result = tx.broadcast()
    if result == 'Transaction Submitted':
        return bytes_to_hex(tx.txid()[::-1])
    raise UpstreamError(result)


def address_type(addr, _network=None):
    if addr.startswith(('1', '2', '3', 'm', 'n')):
        try:
            address = base58.decode(addr).rjust(25, b'\x00')
        except Base58DecodeError as e:
            raise InvalidAddress(f"{addr} : {e}") from None
        payload, checksum = address[:-4], address[-4:]
        version_byte, digest = payload[0:1], payload[1:].rjust(20, b'\x00')
        if len(digest) != 20:
            raise InvalidAddress(f"{addr} : Bad Payload") from None
        if sha256(sha256(payload))[:4] != checksum:
            raise InvalidAddress(f"{addr} : Invalid checksum") from None
        try:
            return {network('keyhash', _network): ADDRESS.P2PKH, network('scripthash', _network): ADDRESS.P2SH}[version_byte]
        except KeyError:
            raise InvalidAddress(f"{addr} : Invalid version byte") from None
    elif addr.startswith(network('hrp', _network)):
        try:
            witness_version, witness_program = bech32.decode(network('hrp', _network), addr)
        except Bech32DecodeError as e:
            raise InvalidAddress(f"{addr} : {e}") from None

        if not witness_version == 0x00:
            raise InvalidAddress(f"{addr} : Invalid witness version") from None
        if len(witness_program) == 20:
            return ADDRESS.P2WPKH
        elif len(witness_program) == 32:
            return ADDRESS.P2WSH
        else:
            raise InvalidAddress(f"{addr} : Invalid witness program") from None
    else:
        raise InvalidAddress(f"{addr} : Invalid leading character") from None


def vanity(prefix: str, _network=None) -> Tuple[str, str, str]:
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


