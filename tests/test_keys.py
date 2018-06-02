
import unittest
import urllib
import urllib.request
import urllib.parse
from lxml import etree
from os import urandom
import secrets

from ECDSA.secp256k1 import PrivateKey, PublicKey, generate_keypair, Message, CURVE
from message import Signature
from transformations import hex_to_bytes, hex_to_int
from btctools.HD.bip32 import Xprv, Xpub


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
        self.assertFalse(message.verify(sig, fake_public))
        self.assertFalse(message.verify(fake_sig, public))
        self.assertFalse(fake_message.verify(sig, public))

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

        # Test padding
        sig = Signature(secrets.randbelow(10**8), secrets.randbelow(10**8))
        self.assertEqual(sig, Signature.decode(sig.encode()))


class TestHD(unittest.TestCase):
    """https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors"""

    def test_1(self):
        m = Xprv.from_seed('000102030405060708090a0b0c0d0e0f')

        self.assertEqual(m.encode(), 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi')
        self.assertEqual(m.to_xpub().encode(), 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8')

        xprv = m/0.
        self.assertEqual(xprv.encode(), 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7')
        self.assertEqual(xprv.to_xpub().encode(), 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw')

        xprv = m/0./1
        self.assertEqual(xprv.encode(), 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs')
        self.assertEqual(xprv.to_xpub().encode(), 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ')

        xprv = m / 0. / 1 / 2.
        self.assertEqual(xprv.encode(), 'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM')
        self.assertEqual(xprv.to_xpub().encode(), 'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5')

        xprv = m / 0. / 1 / 2. / 2
        self.assertEqual(xprv.encode(), 'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334')
        self.assertEqual(xprv.to_xpub().encode(), 'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV')

        xprv = m / 0. / 1 / 2. / 2 / 1000000000
        self.assertEqual(xprv.encode(), 'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76')
        self.assertEqual(xprv.to_xpub().encode(), 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy')

    def test_2(self):
        m = Xprv.from_seed('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542')

        self.assertEqual(m.encode(), 'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U')
        self.assertEqual(m.to_xpub().encode(), 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB')

        xprv = m/0
        self.assertEqual(xprv.encode(), 'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt')
        self.assertEqual(xprv.to_xpub().encode(), 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH')

        xprv = xprv / 2147483647.
        self.assertEqual(xprv.encode(),
                         'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9')
        self.assertEqual(xprv.to_xpub().encode(),
                         'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a')

        xprv = xprv / 1
        self.assertEqual(xprv.encode(),
                         'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef')
        self.assertEqual(xprv.to_xpub().encode(),
                         'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon')

        xprv = xprv / 2147483646.
        self.assertEqual(xprv.encode(),
                         'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc')
        self.assertEqual(xprv.to_xpub().encode(),
                         'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL')

        xprv = xprv / 2
        self.assertEqual(xprv.encode(),
                         'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j')
        self.assertEqual(xprv.to_xpub().encode(),
                         'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt')

    def test_3(self):

        m = Xprv.from_seed('4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be')

        self.assertEqual(m.encode(), 'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6')
        self.assertEqual(m.to_xpub().encode(), 'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13')

        xprv = m / 0.
        self.assertEqual(xprv.encode(), 'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L')
        self.assertEqual(xprv.to_xpub().encode(), 'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y')

