import os
from enum import Enum, unique
from .opcodes import ADDRESS


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
    'extended_prv': {
        ADDRESS.P2PKH: b'\x04\x88\xad\xe4',
        ADDRESS.P2SH: b'\x04\x88\xad\xe4',
        ADDRESS.P2WPKH: b'\x04\xb2\x43\x0c',
        ADDRESS.P2WSH: b'\x02\xaa\x7a\x99',
        ADDRESS.P2WPKH_P2SH: b'\x04\x9d\x78\x78',
        ADDRESS.P2WSH_P2SH: b'\x02\x95\xb4\x3f'
    },
    'extended_pub': {
        ADDRESS.P2PKH: b'\x04\x88\xb2\x1e',
        ADDRESS.P2SH: b'\x04\x88\xb2\x1e',
        ADDRESS.P2WPKH: b'\x04\xb2\x47\x46',
        ADDRESS.P2WSH: b'\x02\xaa\x7e\xd3',
        ADDRESS.P2WPKH_P2SH: b'\x04\x9d\x7c\xb2',
        ADDRESS.P2WSH_P2SH: b'\x02\x95\xb4\x3f'
    },
    'utxo_url': 'https://blockchain.info/unspent?active={address}',
    'rawtx_url': 'https://blockchain.info/rawtx/{txid}?format=hex',
    'broadcast_url': 'https://blockchain.info/pushtx'

}

test = {
    'hrp': 'tb',
    'keyhash': b'\x6f',
    'scripthash': b'\xc4',
    'wif': b'\xef',
    'extended_prv': {
        ADDRESS.P2PKH: b'\x04\x35\x83\x94',
        ADDRESS.P2SH: b'\x04\x35\x83\x94',
        ADDRESS.P2WPKH: b'\x04\x5f\x18\xbc',
        ADDRESS.P2WSH: b'\x02\x57\x50\x48',
        ADDRESS.P2WPKH_P2SH: b'\x04\x4a\x4e\x28',
        ADDRESS.P2WSH_P2SH: b'\x02\x42\x85\xb5'
    },
    'extended_pub': {
        ADDRESS.P2PKH: b'\x04\x35\x87\xcf',
        ADDRESS.P2SH: b'\x04\x35\x87\xcf',
        ADDRESS.P2WPKH: b'\x04\x5f\x1c\xf6',
        ADDRESS.P2WSH: b'\x02\x57\x54\x83',
        ADDRESS.P2WPKH_P2SH: b'\x04\x4a\x52\x62',
        ADDRESS.P2WSH_P2SH: b'\x02\x42\x89\xef'
    },
    'utxo_url': 'https://testnet.blockchain.info/unspent?active={address}',
    'rawtx_url': 'https://testnet.blockchain.info/rawtx/{txid}?format=hex',
    'broadcast_url': 'https://testnet.blockchain.info/pushtx'
}

networks = {
    NETWORK.MAIN: main,
    NETWORK.TEST: test
}


def network(attr):
    net = networks[current_network]
    return net[attr]
