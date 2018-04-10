
import unittest
import urllib
import urllib.request
import urllib.parse
from lxml import etree
from os import urandom
import secrets

from ECDS.secp256k1 import PrivateKey, PublicKey, generate_keypair, Message, CURVE
from message import Signature
from transformations import hex_to_bytes, hex_to_int


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


class TestSignature(unittest.TestCase):

    def test_signing(self):
        message = Message(urandom(32))
        private, public = generate_keypair()
        sig = message.sign(private)

        fake_sig = Signature(sig.r + 1, sig.s - 1)
        _, fake_public = generate_keypair()
        fake_message = Message.from_int(message.int() + 1)

        self.assertTrue(message.verify(sig, public))
        self.assertTrue(not message.verify(sig, fake_public))
        self.assertTrue(not message.verify(fake_sig, public))
        self.assertTrue(not fake_message.verify(sig, public))

    def test_encoding(self):
        raw_sig = hex_to_bytes('304402206878b5690514437a2342405029426cc2b25b4a03fc396fef845d656cf62bad2c022018610a8d37e3384245176ab49ddbdbe8da4133f661bf5ea7ad4e3d2b912d856f')

        sig = Signature.decode(raw_sig)

        self.assertEqual(sig.r, 47253809947851177065887724633329625063088643784040492056218945870752194997548)
        self.assertEqual(sig.s, 11026965355983493404719379810734327200902731292741433431270495068542334764399)

        self.assertEqual(sig.encode(), raw_sig)

        r = hex_to_int('316eb3cad8b66fcf1494a6e6f9542c3555addbf337f04b62bf4758483fdc881d')
        s = hex_to_int('bf46d26cef45d998a2cb5d2d0b8342d70973fa7c3c37ae72234696524b2bc812')
        raw_sig = hex_to_bytes('30450220316eb3cad8b66fcf1494a6e6f9542c3555addbf337f04b62bf4758483fdc881d022100bf46d26cef45d998a2cb5d2d0b8342d70973fa7c3c37ae72234696524b2bc812')

        sig = Signature(r, s)
        self.assertEqual(sig.encode(), raw_sig)
        self.assertEqual(sig, Signature.decode(raw_sig))

        sig = Signature(secrets.randbelow(CURVE.N), secrets.randbelow(CURVE.N))
        self.assertEqual(sig, Signature.decode(sig.encode()))

