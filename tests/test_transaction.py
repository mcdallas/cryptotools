import unittest
from btctools.transaction import Transaction
from transformations import *


class TestTransaction(unittest.TestCase):

    def test_deserialize(self):
        # https://bchain.info/BTC/tx/96534da2f213367a6d589f18d7d6d1689748cd911f8c33a9aee754a80de166be
        tx = hex_to_bytes(
            '01000000'  # version
            '01'  # input count
            '75db462b20dd144dd143f5314270569c0a61191f1378c164ce4262e9bff1b079'  # previous output hash
            '00000000'  # previous output index
            '8b'  # script length
            '4830450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c703302203b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31014104bca69c59dc7a6d8ef4d3043bdcb626e9e29837b9beb143168938ae8165848bfc788d6ff4cdf1ef843e6a9ccda988b323d12a367dd758261dd27a63f18f56ce77'  # scriptSig
            'ffffffff'  # sequence
            '01'  # output count
            '33f5010000000000'  # value (in satoshis)
            '19'  # script length
            '76a914dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac'  # scriptPubKey  
            '00000000'  # lock time
        )

        trans = Transaction.deserialize(tx)
        assert len(trans.inputs) == 1
        assert len(trans.outputs) == 1
        assert trans.json()['txid'] == '96534da2f213367a6d589f18d7d6d1689748cd911f8c33a9aee754a80de166be'
        assert trans.serialize() == tx

