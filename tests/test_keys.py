
import unittest
import urllib
import urllib.request
import urllib.parse
import pathlib
import secrets
import json
from lxml import etree
from os import urandom


from ECDSA.secp256k1 import PrivateKey, PublicKey, generate_keypair, Message, CURVE
from btctools.network import NETWORK
from message import Signature
from transformations import hex_to_bytes, hex_to_int, bytes_to_hex
from btctools.HD.bip32 import Xprv, Xpub
from btctools.HD import to_seed
from btctools.opcodes import ADDRESS

HERE = pathlib.Path(__file__).parent.absolute()


class TestPubKey(unittest.TestCase):

    def test_compression(self):
        prv, pub = generate_keypair()

        encoded = pub.encode(compressed=True)
        self.assertEqual(PublicKey.decode(encoded), pub)

        encoded = pub.encode(compressed=False)
        self.assertEqual(PublicKey.decode(encoded), pub)

    def test_compression_test_network(self):
        prv, pub = generate_keypair(NETWORK.TEST)

        encoded = pub.encode(compressed=True)
        self.assertEqual(PublicKey.decode(encoded, _network=NETWORK.TEST), pub)

        encoded = pub.encode(compressed=False)
        self.assertEqual(PublicKey.decode(encoded, _network=NETWORK.TEST), pub)


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
        sig_high_s = hex_to_bytes('30450220316eb3cad8b66fcf1494a6e6f9542c3555addbf337f04b62bf4758483fdc881d022100bf46d26cef45d998a2cb5d2d0b8342d70973fa7c3c37ae72234696524b2bc812')
        sig_low_s = hex_to_bytes('30440220316eb3cad8b66fcf1494a6e6f9542c3555addbf337f04b62bf4758483fdc881d022040b92d9310ba26675d34a2d2f47cbd27b13ae26a7310f1c99c8bc83a850a792f')

        sig_high = Signature(r, s, force_low_s=False)
        sig_low = Signature(r, s, force_low_s=True)
        self.assertEqual(sig_low.encode(), sig_low_s)
        self.assertEqual(sig_high.encode(), sig_high_s)
        self.assertEqual(sig_low, Signature.decode(sig_high_s))
        self.assertEqual(sig_low, Signature.decode(sig_low_s))

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

    def test_btct(self):
        m = Xprv.from_seed('01dbae76e4b27ccf8b6eeb94885a4d6d80ba3c92ae75596b320e545e40ffe8db6d54cb0a7068887fbc62dbf96ba2655e35e721a5c50b97619d04335310acc3fb', _network=NETWORK.TEST)

        self.assertEqual(m.encode(), 'tprv8ZgxMBicQKsPfJh9gLmR6zJavmYD8cJ6Geh1iMY6h74C3FE91hrY5xnBJaru78UzqomD8ayq5RSJvnpKzhG8JV3F7uWbWjHqQVZCzX9S4cw')

        xprv = m / 0
        self.assertEqual(xprv.encode(), 'tprv8bbw6WEEHUSQhYgnekoRRzjdvNfqZRCzmpvEjmcRV57BepgHb9rDmktrPjwZzP3yj34vviGQr4vUgpvuGjKJdWbEJjiKALLrjmPc6GhyZ1e')
        self.assertEqual(xprv.to_xpub().encode(), 'tpubD8HyEvGURr85b1iaYQU1qQPkVQBmikPuM8X22HeiuLuaVJw4DYfoxFWiZuEasTawEoUSJxZuKoQUJ634yuqirY5tXJSb1ZVj4suBfUfBsUx')

    def test_bip39(self):
        with open(HERE / 'vectors' / 'mnemonic.txt') as fileobj:
            data = json.load(fileobj)

        for entropy, mnemonic, seed, master in data['english']:
            my_seed = to_seed(mnemonic, passphrase='TREZOR')
            self.assertEqual(bytes_to_hex(my_seed), seed)
            xprv = Xprv.from_seed(seed)
            self.assertEqual(xprv.encode(), master)

    def test_bip49(self):
        """https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki#Test_vectors"""

        import os
        os.environ['CRYPTOTOOLS_NETWORK'] = 'test'

        mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        m = Xprv.from_mnemonic(mnemonic)
        self.assertEqual(m.encode(), 'tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd')

        xprv = m/49./1./0.
        self.assertEqual(xprv.encode(), 'tprv8gRrNu65W2Msef2BdBSUgFdRTGzC8EwVXnV7UGS3faeXtuMVtGfEdidVeGbThs4ELEoayCAzZQ4uUji9DUiAs7erdVskqju7hrBcDvDsdbY')

        xprv = m/49./1./0./0/0
        self.assertEqual(xprv.key.wif(compressed=True), 'cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ')
        self.assertEqual(xprv.key.hex(), 'c9bdb49cfbaedca21c4b1f3a7803c34636b1d7dc55a717132443fc3f4c5867e8')
        self.assertEqual(xprv.to_xpub().key.hex(compressed=True), '03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f')
        self.assertEqual(xprv.key.to_public().to_address('P2WPKH-P2SH'), '2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2')

        os.environ['CRYPTOTOOLS_NETWORK'] = 'main'

    def test_bip49_network_variable(self):
        """https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki#Test_vectors"""

        mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        m = Xprv.from_mnemonic(mnemonic, _network=NETWORK.TEST)
        self.assertEqual(m.encode(), 'tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd')

        xprv = m/49./1./0.
        self.assertEqual(xprv.encode(), 'tprv8gRrNu65W2Msef2BdBSUgFdRTGzC8EwVXnV7UGS3faeXtuMVtGfEdidVeGbThs4ELEoayCAzZQ4uUji9DUiAs7erdVskqju7hrBcDvDsdbY')

        xprv = m/49./1./0./0/0
        self.assertEqual(xprv.key.wif(compressed=True), 'cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ')
        self.assertEqual(xprv.key.hex(), 'c9bdb49cfbaedca21c4b1f3a7803c34636b1d7dc55a717132443fc3f4c5867e8')
        self.assertEqual(xprv.to_xpub().key.hex(compressed=True), '03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f')
        self.assertEqual(xprv.key.to_public().to_address('P2WPKH-P2SH'), '2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2')

    def test_bip84(self):
        """https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki#test-vectors"""

        mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        m = Xprv.from_mnemonic(mnemonic, addresstype='P2WPKH')
        M = m.to_xpub()

        self.assertEqual(m.encode(), 'zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5')
        self.assertEqual(M.encode(), 'zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF')

        xprv = m/84./0./0.
        self.assertEqual(xprv.encode(), 'zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE')
        self.assertEqual(xprv.to_xpub().encode(), 'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs')

        xprv = m/84./0./0./0/0
        self.assertEqual(xprv.key.wif(compressed=True), 'KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d')
        self.assertEqual(xprv.to_xpub().key.hex(compressed=True), '0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c')
        self.assertEqual(xprv.address(), 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu')

        xprv = m/84./0./0./0/1
        self.assertEqual(xprv.key.wif(compressed=True), 'Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy')
        self.assertEqual(xprv.to_xpub().key.hex(compressed=True), '03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77')
        self.assertEqual(xprv.address(), 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g')

        xprv = m/84./0./0./1/0
        self.assertEqual(xprv.key.wif(compressed=True), 'KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF')
        self.assertEqual(xprv.to_xpub().key.hex(compressed=True), '03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6')
        self.assertEqual(xprv.address(), 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el')

    def test_bip84_network_variable(self):
        """https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki#test-vectors"""

        mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        m = Xprv.from_mnemonic(mnemonic, addresstype='P2WPKH', _network=NETWORK.MAIN)
        M = m.to_xpub()

        self.assertEqual(m.encode(), 'zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5')
        self.assertEqual(M.encode(), 'zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF')

        xprv = m/84./0./0.
        self.assertEqual(xprv.encode(), 'zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE')
        self.assertEqual(xprv.to_xpub().encode(), 'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs')

        xprv = m/84./0./0./0/0
        self.assertEqual(xprv.key.wif(compressed=True), 'KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d')
        self.assertEqual(xprv.to_xpub().key.hex(compressed=True), '0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c')
        self.assertEqual(xprv.address(), 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu')

        xprv = m/84./0./0./0/1
        self.assertEqual(xprv.key.wif(compressed=True), 'Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy')
        self.assertEqual(xprv.to_xpub().key.hex(compressed=True), '03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77')
        self.assertEqual(xprv.address(), 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g')

        xprv = m/84./0./0./1/0
        self.assertEqual(xprv.key.wif(compressed=True), 'KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF')
        self.assertEqual(xprv.to_xpub().key.hex(compressed=True), '03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6')
        self.assertEqual(xprv.address(), 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el')

    def test_decode_bip84(self):
        prv = 'zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5'
        m = Xprv.decode(prv)
        self.assertEqual(m.type, ADDRESS.P2WPKH)
        self.assertTrue(m.is_master())

        xprv = Xprv.decode('zprvAg4yBxbZcJpcLxtXp5kZuh8jC1FXGtZnCjrkG69JPf96KZ1TqSakA1HF3EZkNjt9yC4CTjm7txs4sRD9EoHLgDqwhUE6s1yD9nY4BCNN4hw')
        xpub = Xpub.decode('zpub6u4KbU8TSgNuZSxzv7HaGq5Tk361gMHdZxnM4UYuwzg5CMLcNytzhobitV4Zq6vWtWHpG9QijsigkxAzXvQWyLRfLq1L7VxPP1tky1hPfD4')
        self.assertEqual(xprv.to_xpub(), xpub)
        self.assertEqual(xprv.path, "m/x/x/x/0")
        self.assertEqual(xpub.path, "M/x/x/x/0")

    def test_decode_bip84_network_variable(self):
        prv = 'zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5'
        m = Xprv.decode(prv, _network=NETWORK.MAIN)
        self.assertEqual(m.type, ADDRESS.P2WPKH)
        self.assertTrue(m.is_master())

        xprv = Xprv.decode('zprvAg4yBxbZcJpcLxtXp5kZuh8jC1FXGtZnCjrkG69JPf96KZ1TqSakA1HF3EZkNjt9yC4CTjm7txs4sRD9EoHLgDqwhUE6s1yD9nY4BCNN4hw')
        xpub = Xpub.decode('zpub6u4KbU8TSgNuZSxzv7HaGq5Tk361gMHdZxnM4UYuwzg5CMLcNytzhobitV4Zq6vWtWHpG9QijsigkxAzXvQWyLRfLq1L7VxPP1tky1hPfD4')
        self.assertEqual(xprv.to_xpub(), xpub)
        self.assertEqual(xprv.path, "m/x/x/x/0")
        self.assertEqual(xpub.path, "M/x/x/x/0")

    def test_decode_bip49(self):

        prv = 'yprvABrGsX5C9jantZVwdwcQhDXkqsu4RoSAZKBwPnLA3uyeVM3C3fvTuqzru4fovMSLqYSqALGe9MBqCf7Pg7Y7CTsjoNnLYg6HxR2Xo44NX7E'
        m = Xprv.decode(prv)
        self.assertEqual(m.type, ADDRESS.P2WPKH_P2SH)
        self.assertTrue(m.is_master())

        xprv = Xprv.decode('yprvAKoaYbtSYB8DmmBt2Z7TgukWphdCiSMRVdzDK3aHUSna8jo6xnG41jQ11ToPk4SQnE5sau6CYK4od9fyz53mK7huW4JskyMMEmixACuyhhr')
        xpub = Xpub.decode('ypub6Ynvx7RLNYgWzFGM8aeU43hFNjTh7u5Grrup7Ryu2nKZ1Y8FWKaJZXiUrkJSnMmGVNBoVH1DNDtQ32tR4YFDRSpSUXjjvsiMnCvoPHVWXJP')

        self.assertEqual(xprv.to_xpub(), xpub)
        self.assertEqual(xprv.path, "m/x/x/x/0")
        self.assertEqual(xpub.path, "M/x/x/x/0")

    def test_decode_bip49_network_variable(self):

        prv = 'yprvABrGsX5C9jantZVwdwcQhDXkqsu4RoSAZKBwPnLA3uyeVM3C3fvTuqzru4fovMSLqYSqALGe9MBqCf7Pg7Y7CTsjoNnLYg6HxR2Xo44NX7E'
        m = Xprv.decode(prv, _network=NETWORK.MAIN)
        self.assertEqual(m.type, ADDRESS.P2WPKH_P2SH)
        self.assertTrue(m.is_master())

        xprv = Xprv.decode('yprvAKoaYbtSYB8DmmBt2Z7TgukWphdCiSMRVdzDK3aHUSna8jo6xnG41jQ11ToPk4SQnE5sau6CYK4od9fyz53mK7huW4JskyMMEmixACuyhhr')
        xpub = Xpub.decode('ypub6Ynvx7RLNYgWzFGM8aeU43hFNjTh7u5Grrup7Ryu2nKZ1Y8FWKaJZXiUrkJSnMmGVNBoVH1DNDtQ32tR4YFDRSpSUXjjvsiMnCvoPHVWXJP')

        self.assertEqual(xprv.to_xpub(), xpub)
        self.assertEqual(xprv.path, "m/x/x/x/0")
        self.assertEqual(xpub.path, "M/x/x/x/0")
