import unittest
import secrets
import urllib.request
import urllib.parse

from html.parser import HTMLParser

from cryptotools.btctools.address import pubkey_to_address, script_to_address, hash160, address_to_script, address_type, ADDRESS
from cryptotools.btctools.script import push, OP
from cryptotools.ECDSA.secp256k1 import generate_keypair, PrivateKey, PublicKey
from cryptotools.transformations import bytes_to_hex, int_to_str
from cryptotools.btctools import bech32


class HtmlLegacyAddress(HTMLParser):
    def __init__(self):
        self.private = None
        self.public = None
        self.address = None
        super().__init__()
    def handle_starttag(self, tag, attrs):
        if tag == 'input':
            attrs = dict(attrs)
            name, value = attrs.get('name'), attrs.get('value')
            if name == 'private' and self.private is None:
                self.private = value
            if name == 'public' and self.public is None:
                self.public = value
            if name == 'Base58' and self.address is None:
                self.address = value


class TestLegacyAddress(unittest.TestCase):

    url = 'https://gobittest.appspot.com/Address'

    def test_p2pkh(self):
        """https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses#See_Also"""

        payload = {'Random': 'Random'}
        data = urllib.parse.urlencode(payload).encode('ascii')
        req = urllib.request.Request(self.url, data)

        with urllib.request.urlopen(req) as response:
            html = HtmlLegacyAddress()
            html.feed(response.read().decode('utf-8'))

        private, public, address = html.private, html.public, html.address

        my_pubkey = PrivateKey.from_hex(private).to_public()

        self.assertEqual(public.lower(), my_pubkey.hex())
        self.assertEqual(pubkey_to_address(my_pubkey), address)
        self.assertEqual(address_type(address), ADDRESS.P2PKH)

    def test_p2sh(self):
        script = secrets.token_bytes(32)
        scripthash = hash160(script)

        payload = {'RIPEMDWithHash': '05' + bytes_to_hex(scripthash)}
        data = urllib.parse.urlencode(payload).encode('ascii')
        req = urllib.request.Request(self.url, data)

        with urllib.request.urlopen(req) as response:
            html = HtmlLegacyAddress()
            html.feed(response.read().decode('utf-8'))

        address = html.address

        self.assertEqual(script_to_address(script, 'P2SH'), address)
        self.assertEqual(address_type(address), ADDRESS.P2SH)

    # def test_balance(self):
    #     # if satoshi moves his coins this test will fail
    #     addr = Address('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
    #     self.assertEqual(addr.balance(), 66.65271233)

    def test_address_type(self):
        self.assertEqual(address_type('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'), ADDRESS.P2PKH)
        self.assertEqual(address_type('34eBzenHJEdk5PK9ojuuBZvCRtNhvvysYZ'), ADDRESS.P2SH)


class TestBech32(unittest.TestCase):
    hrp = 'bc'
    witver = 0x00

    def test_bech32_decode(self):
        private, public = generate_keypair()

        witprog = hash160(public.encode(compressed=True))
        address = bech32.encode(self.hrp, self.witver, witprog)
        wv, decoded = bech32.decode(self.hrp, address)
        self.assertEqual(wv, self.witver)
        self.assertEqual(bytes(decoded), bytes(witprog))

    def test_p2wpkh(self):
        """https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#examples"""
        pubkey = PublicKey.from_hex('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')
        self.assertEqual(bech32.encode(self.hrp, self.witver, hash160(pubkey.encode(compressed=True))), 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')
        address = pubkey_to_address(pubkey, version='P2WPKH')
        self.assertEqual(address, 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')
        self.assertEqual(address_type(address), ADDRESS.P2WPKH)

    def test_p2wsh(self):
        """https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#examples"""
        pubkey = PublicKey.from_hex('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')
        script = push(pubkey.encode(compressed=True)) + OP.CHECKSIG.byte  # <key> <OP_CHECKSIG>
        address = script_to_address(script, 'P2WSH')
        self.assertEqual(address, 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3')
        self.assertEqual(address_type(address), ADDRESS.P2WSH)

    def test_valid_bech32(self):
        """https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#test-vectors"""

        valid_strings = [
            'A12UEL5L',
            'a12uel5l',
            'an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs',
            'abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw',
            '11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j',
            'split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w',
            '?1ezyfcl'
        ]

        invalid_strings = [
            int_to_str(0x20) + '1nwldj5',
            int_to_str(0x7F) + '1axkwrx',
            b'\x80'.decode('ascii', 'replace') + '1eym55h',
            'an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx',
            'pzry9x0s0muk',
            '1pzry9x0s0muk',
            'x1b4n0q5v',
            'li1dgmt3',
            'de1lg7wt' + b'\xff'.decode('ascii', 'replace'),
            'A1G7SGD8',
            '10a06t8',
            '1qzzfhee'
        ]
        # Should raise no exceptions
        for string in valid_strings:
            bech32.bech32_decode(string)

        # Should raise Bech32DecodeError
        for string in invalid_strings:
            with self.assertRaises(bech32.Bech32DecodeError):
                bech32.bech32_decode(string)

    def test_address_to_script(self):
        """https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#test-vectors"""
        valid = {
            'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4': '0014751e76e8199196d454941c45d1b3a323f1433bd6',
            'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7': '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262',
            'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx': '5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6',
            'BC1SW50QA3JX3S': '6002751e',
            'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj': '5210751e76e8199196d454941c45d1b3a323',
            'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy': '0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'
        }

        invalid = [
            'tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty',
            'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5',
            'BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2',
            'bc1rw5uspcuh',
            'bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90',
            'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P',
            'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7',
            'bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du',
            'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv',
            'bc1gmk9yu'
        ]

        for addr, script in valid.items():
            self.assertEqual(bytes_to_hex(address_to_script(addr)), script)

        for addr in invalid:
            with self.assertRaises(bech32.Bech32DecodeError):
                address_to_script(addr)

    def test_address_type(self):
        self.assertEqual(address_type('bc1qh2egksgfejqpktc3kkdtuqqrukrpzzp9lr0phn'), ADDRESS.P2WPKH)
        self.assertEqual(address_type('bc1q8yh8l8ft3220q328hlapqhflpzy6xvkq6u36mctk8gq5pyxm3rwqv5h5dg'), ADDRESS.P2WSH)


class TestNet(unittest.TestCase):

    def setUp(self):
        import os
        os.environ['CRYPTOTOOLS_NETWORK'] = 'test'

    def tearDown(self):
        import os
        os.environ['CRYPTOTOOLS_NETWORK'] = 'main'

    def test_address_type(self):
        self.assertEqual(address_type('mgxVT9fzHwYDsgEGJSZekKgYbAyrBkqdpi'), ADDRESS.P2PKH)
        self.assertEqual(address_type('2MzAQDXGpmJyS6ybm2q57dbe8j2oxmvRDkc'), ADDRESS.P2SH)
        self.assertEqual(address_type('n2NGrooSecJaiD6ssp4YqFoj9eZ7GrCJ66'), ADDRESS.P2PKH)
        self.assertEqual(address_type('tb1q7w5dhw4hl5yvxvl3yvv2xxvh7jwm28p9kpelcp'), ADDRESS.P2WPKH)
