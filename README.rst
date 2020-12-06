About this repo
---------------

Barebones Python 3.6+ implementation (no dependencies/standard lib only) of some common cryptographic functions for educational purposes.
Feel free to fork the repo and play around with it. Performance is ..abysmal but otherwise it works fine. Please do not
use this for anything serious because I am not a security expert.


Install
-------

.. code-block:: bash

    $ pip install git+https://github.com/mcdallas/cryptotools.git@master#egg=cryptotools


Examples
--------

HD Wallets

.. code-block:: Python

    from cryptotools.BTC import Xprv

    >>> m = Xprv.from_mnemonic('impulse prize erode winner pupil fun off addict ...')
    >>> m.encode()
    'xprv9s21ZrQH143K38bNJiHY54kkjio8o6aw3bRjCbzi8KgRxNy98avUribz1wk85ToSUV2VwVuc73NJWc2YGwpMtqz7bBFUh9Q77RtJeuh2zvy'

    >>> m/44/0/0/0
    Xprv(path=m/44/0/0/0, key=L1WKXyMwKnp8wPwAtjwiKWunACY5RSUXAzmS6jDRRHcHnDbeRiKu)

    >>> m/0./123/5.  # Use floats for hardened path, alternative is // e.g m//0/123//5
    Xprv(path=m/0h/123/5h, key=L3qskbdzgNu4kwjx2QU63q59khpEHVaSbqd2Pc268Jngiha6mbfQ)

    >>> M = m.to_xpub()

    >>> (m/123/456).to_xpub() == M/123/456
    True

    >>> (m/44./0./0./0/0).address('P2PKH')  # bip44
    '1BTYXdyrBh1yRCDpqyDhoQG896bnzqtaPz'

    >>> (m/84./0./0./0/0).address('P2WPKH')  # bip84
    'bc1qjnx8cq32z2t72tsmuwql3wz22lywlpcm3w52lk'


Sign/Verify message:

.. code-block:: Python

    from cryptotools.ECDSA.secp256k1 import generate_keypair, Message

    private, public = generate_keypair()

    >>> message = Message.from_str('kinakuta')
    >>> signature = message.sign(private)
    >>> message.verify(signature, public)
    True



Verify a transaction:

.. code-block:: Python

    from cryptotools.BTC import Transaction

    tx = Transaction.get('454e575aa1ed4427985a9732d753b37dc711675eb7c977637b1eea7f600ed214')

    >>> tx
    Transaction(inputs=1, outputs=2)

    >>> tx.outputs
    [Output(type=P2SH, value=0.0266 BTC),
     Output(type=P2WSH, value=0.00468 BTC)]

    >>> tx.verify()
    True


Create a transaction and submit it automatically

.. code-block:: Python

    import os

    from cryptotools.BTC import PrivateKey, send

    key = PrivateKey.from_hex('mysupersecretkey')

    >>> os.environ['CRYPTOTOOLS_NETWORK'] = 'test'
    >>> send(source='n4SbPWR6EmQMsWaQVYYFXiJgjweGKE4XnQ', to={'n2NGrooSecJaiD6ssp4YqFoj9eZ7GrCJ66': 0.46}, fee=0.01, private=key)
    '907b92969cb3a16ddb45591bf2530f177b7f10cef4e62c331596a84f66c3b8c3'  # txid


Create and broadcast manually

.. code-block:: Python

    import os
    os.environ['CRYPTOTOOLS_NETWORK'] = 'test'

    from cryptotools.BTC import PrivateKey, Address

    private = PrivateKey.from_hex('mysupersecretkey')
    address = Address('n2NGrooSecJaiD6ssp4YqFoj9eZ7GrCJ66')

    >>> address.balance()
    0.55

    >>> send_to = {'n4SbPWR6EmQMsWaQVYYFXiJgjweGKE4XnQ': 0.1, 'n2NGrooSecJaiD6ssp4YqFoj9eZ7GrCJ66': 0.4}
    >>> tx = address.send(to=send_to, fee=0.05, private=private)

    >>> tx
    Transaction(inputs=1, outputs=2)

    >>> tx.inputs[0].is_signed()
    True

    >>> tx.verify()
    True

    >>> tx.broadcast()
    'Transaction Submitted'

Create keys/addresses (including segwit)

.. code-block:: Python

    from cryptotools.BTC import generate_keypair, push, script_to_address, OP
    private, public = generate_keypair()

    >>> private.hex()
    'de4f177274d29f88a5805333e10525f5dd41634455dfadc8849b977802481ccd'

    >>> private.wif(compressed=False)
    '5KWCAYLo35uZ9ibPTzTUDXESTE6ne8p1eXviYMHwaoS4tpvYCAp'

    >>> public.hex()
    '047e30fd478b44869850352daef8f5f7a7b5233044018d465431afdc0b436c973e8df1244189d25ae73d90c90cc0f998eb9784adecaecc46e8c536d7d6845fa26e'

    >>> public.to_address('P2PKH')
    '19dFXDxiD4KrUTNFfcgeekFpQmUC553GzW'

    # Simple <key> <OP_CHECKSIG> script
    >>> script = push(public.encode(compressed=True)) + OP.CHECKSIG.byte
    >>> script_to_address(script, 'P2WSH')
    'bc1q8yh8l8ft3220q328hlapqhflpzy6xvkq6u36mctk8gq5pyxm3rwqv5h5dg'

    # nested P2WSH into P2SH -- use with caution
    >>> script_to_address(script, 'P2WSH-P2SH')
    '34eBzenHJEdk5PK9ojuuBZvCRtNhvvysYZ'

.. code-block:: Python

    from cryptotools.ECDSA.secp256k1 import CURVE, PrivateKey
    private = PrivateKey.random()

    >>> private.int()
    8034465994996476238286561766373949549982328752707977290709076444881813294372

    >>> public = private.to_public()
    >>> public
    PublicKey(102868560361119050321154887315228169307787313299675114268359376451780341556078, 83001804479408277471207716276761041184203185393579361784723900699449806360826)

    >>> public.point in CURVE
    True

    >>> public.to_address('P2WPKH')
    'bc1qh2egksgfejqpktc3kkdtuqqrukrpzzp9lr0phn'


Vanity address generator

.. code-block:: Python

    from cryptotools.BTC.address import vanity

    >>> private, public, address = vanity('Bob')  # Takes forever
    Found address starting with Bob in 1:17:55 after 80,111 tries




RSA

.. code-block:: Python


    from cryptotools import RSA
    private, public = RSA.generate_keypair(512)

    >>> txt = 'deadbeef'
    >>> message = RSA.Message.from_hex(txt)
    >>> message
    b'\xde\xad\xbe\xef'


    >>> message.encrypt(public)
    >>> message
    b'\x05\xe3q\x92\x1c=)\xaev\xe8\x8d\x8c\x9f\x8d\xde\x17\xdc\x95y\x1e\x90N\xf1A\x816\xb7|z\x83...'

    >>> message.decrypt(private)
    >>> message.hex() == txt
    True

    >>> message.encrypt(private)
    >>> message.decrypt(public)
    >>> message.hex() == txt
    True


to run tests

.. code-block:: bash

   $ python -m unittest

from the project directory
