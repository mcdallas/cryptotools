About this repo
---------------

Barebones Python 3.6+ implementation (no dependencies/standard lib only) of some common cryptographic functions for educational purposes.
Feel free to fork the repo and play around with it. Performance is ..abysmal but otherwise it works fine. Please do not
use this for anything serious because I am not a security expert.


Examples
--------

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

ECDS

.. code-block:: Python

    from ECDS.secp256k1 import generate_keypair, Message

    >>> private, public = generate_keypair()

    >>> message = Message.from_str('kinakuta')
    >>> signature = message.sign(private)
    >>> message.verify(signature, public)
    True


btctools

.. code-block:: Python

    >>> from transformations import bytes_to_hex
    >>> from btctools.address import pubkey_to_address
    >>> from ECDS.secp256k1 import generate_keypair

    >>> private, public = generate_keypair()

    >>> bytes_to_hex(private)
    'de4f177274d29f88a5805333e10525f5dd41634455dfadc8849b977802481ccd'

    >>> bytes_to_hex(public)
    '047e30fd478b44869850352daef8f5f7a7b5233044018d465431afdc0b436c973e8df1244189d25ae73d90c90cc0f998eb9784adecaecc46e8c536d7d6845fa26e'

    >>> pubkey_to_address(public, version='P2PKH')
    '19dFXDxiD4KrUTNFfcgeekFpQmUC553GzW'

.. code-block:: Python

    >>> import secrets
    >>> from ECDS.secp256k1 import CURVE, encode_public_key
    >>> from btctools.address import pubkey_to_address

    >>> private_key = secrets.randbelow(CURVE.N)
    >>> private_key
    8034465994996476238286561766373949549982328752707977290709076444881813294372

    >>> public_key = CURVE.G * private_key
    >>> public_key
    Point(102868560361119050321154887315228169307787313299675114268359376451780341556078, 83001804479408277471207716276761041184203185393579361784723900699449806360826, secp256k1)

    >>> public_key in CURVE
    True

    >>> pubkey_to_address(encode_public_key(public_key), version='P2SH')
    '3DMWLzufL1qbfPe9xqsUAT1tRLUQ2qRdhQ'


vanitygen

.. code-block:: Python

    >>> from btctools.address import vanity

    >>> private, public, address = vanity('Bob')  # Takes forever
    Found address starting with Bob in 1:17:55 after 80,111 tries

