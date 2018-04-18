About this repo
---------------

Barebones Python 3.6+ implementation (no dependencies/standard lib only) of some common cryptographic functions for educational purposes.
Feel free to fork the repo and play around with it. Performance is ..abysmal but otherwise it works fine. Please do not
use this for anything serious because I am not a security expert.


Examples
--------

ECDSA

.. code-block:: Python

    from ECDSA.secp256k1 import generate_keypair, Message

    >>> private, public = generate_keypair()

    >>> message = Message.from_str('kinakuta')
    >>> signature = message.sign(private)
    >>> message.verify(signature, public)
    True


btctools

.. code-block:: Python

    from btctools import Transaction

    tx = Transaction.get('454e575aa1ed4427985a9732d753b37dc711675eb7c977637b1eea7f600ed214')

    >>> tx
    Transaction(inputs=1, outputs=2)

    tx.outputs

    [Output(type=P2SH, value=0.0266 BTC),
     Output(type=P2WSH, value=0.00468 BTC)]

    >>> tx.verify()
    True

.. code-block:: Python

    >>> from btctools import generate_keypair, push, script_to_address, TX

    >>> private, public = generate_keypair()

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

    # nested P2WSH into P2SH
    >>> script_to_address(script, 'P2WSH-P2SH')
    '34eBzenHJEdk5PK9ojuuBZvCRtNhvvysYZ'

.. code-block:: Python

    >>> from ECDSA.secp256k1 import CURVE, PrivateKey

    >>> private = PrivateKey.random()
    >>> private.int()
    8034465994996476238286561766373949549982328752707977290709076444881813294372

    >>> public = private.to_public()
    >>> public
    PublicKey(102868560361119050321154887315228169307787313299675114268359376451780341556078, 83001804479408277471207716276761041184203185393579361784723900699449806360826)

    >>> public.point in CURVE
    True

    >>> public.to_address('P2WPKH')
    'bc1qh2egksgfejqpktc3kkdtuqqrukrpzzp9lr0phn'



vanitygen

.. code-block:: Python

    >>> from btctools.address import vanity

    >>> private, public, address = vanity('Bob')  # Takes forever
    Found address starting with Bob in 1:17:55 after 80,111 tries




RSA

.. code-block:: Python


    >>> import RSA

    >>> private, public = RSA.generate_keypair(512)

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