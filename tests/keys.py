import secrets
import unittest
import urllib
import urllib.request
import urllib.parse
from lxml import etree

from ECDS.secp256k1 import encode_public_key, decode_public_key, private_to_public, N, decode_private_key, encode_private_key
from transformations import hex_to_bytes, int_to_bytes


class TestPubKey(unittest.TestCase):

    def test_compression(self):
        prv = secrets.randbelow(N)
        pub = private_to_public(prv)

        encoded = encode_public_key(pub, compressed=True)
        self.assertEqual(decode_public_key(encoded), pub)

        encoded = encode_public_key(pub, compressed=False)
        self.assertEqual(decode_public_key(encoded), pub)


class TestPrivKey(unittest.TestCase):

    url = 'http://gobittest.appspot.com/PrivateKey'

    def test_wif(self):

        payload = {'Random': 'Random'}
        data = urllib.parse.urlencode(payload).encode('ascii')
        req = urllib.request.Request(self.url, data)

        with urllib.request.urlopen(req) as response:
            html = response.read()

        tree = etree.HTML(html)

        wif = tree.find('.//input[@name="wif"]').attrib['value']
        private = tree.find('.//input[@name="private2"]').attrib['value']

        my_private = decode_private_key(wif)
        my_wif = encode_private_key(hex_to_bytes(private))

        self.assertEqual(my_private, hex_to_bytes(private))
        self.assertEqual(my_wif, wif)

    def test_compression(self):
        prv = int_to_bytes(secrets.randbelow(N))

        self.assertEqual(decode_private_key(encode_private_key(prv, compressed=False)), prv)
        self.assertEqual(decode_private_key(encode_private_key(prv, compressed=True)), prv)

