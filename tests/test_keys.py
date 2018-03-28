import unittest
import urllib
import urllib.request
import urllib.parse
from lxml import etree

from ECDS.secp256k1 import PrivateKey, PublicKey, generate_keypair


class TestPubKey(unittest.TestCase):

    def test_compression(self):
        prv, pub = generate_keypair()

        encoded = pub.encode(compressed=True)
        self.assertEqual(PublicKey.decode(encoded), pub)

        encoded = pub.encode(compressed=False)
        self.assertEqual(PublicKey.decode(encoded), pub)


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

        my_private = PrivateKey.from_wif(wif)
        my_wif = PrivateKey.from_hex(private).wif()

        self.assertEqual(my_private.hex().lower(), private.lower())
        self.assertEqual(my_wif, wif)

    def test_compression(self):
        prv = PrivateKey.random()

        self.assertEqual(PrivateKey.from_wif(prv.wif(compressed=False)), prv)
        self.assertEqual(PrivateKey.from_wif(prv.wif(compressed=True)), prv)

