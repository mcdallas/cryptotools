import os
from enum import Enum, unique


@unique
class NETWORK(Enum):
    MAIN = 'main'
    TEST = 'test'


current_network = NETWORK(os.environ.get('CRYPTOTOOLS_NETWORK', 'main'))

main = {
    'hrp': 'bc',
    'keyhash': b'\x00',
    'scripthash': b'\x05',
    'wif': b'\x80',
    'utxo_url': 'https://blockchain.info/unspent?active={address}',
    'rawtx_url': 'https://blockchain.info/rawtx/{txid}?format=hex',
    'broadcast_url': 'https://blockchain.info/pushtx'

}

test = {
    'hrp': 'tb',
    'keyhash': b'\x6f',
    'scripthash': b'\xc4',
    'wif': b'\xef',
    'utxo_url': 'https://testnet.blockchain.info/unspent?active={address}',
    'rawtx_url': 'https://testnet.blockchain.info/rawtx/{txid}?format=hex',
    'broadcast_url': 'https://testnet.blockchain.info/pushtx'
}

networks = {
    NETWORK.MAIN: main,
    NETWORK.TEST: test
}

network = networks[current_network]
