import os
from enum import Enum, unique
from .opcodes import ADDRESS


@unique
class NETWORK(Enum):
    MAIN = 'main'
    TEST = 'test'


def current_network():
    return NETWORK(os.environ.get('CRYPTOTOOLS_NETWORK', 'main'))


main = {
    'hrp': 'bc',
    'keyhash': b'\x00',
    'scripthash': b'\x05',
    'wif': b'\x80',
    'extended_prv': {
        # https://github.com/spesmilo/electrum-docs/blob/master/xpub_version_bytes.rst
        ADDRESS.P2PKH: b'\x04\x88\xad\xe4',  # xprv
        ADDRESS.P2WPKH: b'\x04\xb2\x43\x0c',  # zprv
        ADDRESS.P2WSH: b'\x02\xaa\x7a\x99',  # Zprv
        ADDRESS.P2WPKH_P2SH: b'\x04\x9d\x78\x78',  # yprv
        ADDRESS.P2WSH_P2SH: b'\x02\x95\xb4\x3f'  # Yprv
    },
    'extended_pub': {
        # https://github.com/spesmilo/electrum-docs/blob/master/xpub_version_bytes.rst
        ADDRESS.P2PKH: b'\x04\x88\xb2\x1e',  # xpub
        ADDRESS.P2WPKH: b'\x04\xb2\x47\x46',  # zpub
        ADDRESS.P2WSH: b'\x02\xaa\x7e\xd3',  # Zpub
        ADDRESS.P2WPKH_P2SH: b'\x04\x9d\x7c\xb2',  # ypub
        ADDRESS.P2WSH_P2SH: b'\x02\x95\xb4\x3f'  # Ypub
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
        # https://github.com/spesmilo/electrum-docs/blob/master/xpub_version_bytes.rst
        ADDRESS.P2PKH: b'\x04\x35\x83\x94',  # tprv
        ADDRESS.P2WPKH: b'\x04\x5f\x18\xbc',  # vprv
        ADDRESS.P2WSH: b'\x02\x57\x50\x48',  # Vprv
        ADDRESS.P2WPKH_P2SH: b'\x04\x4a\x4e\x28',  # uprv
        ADDRESS.P2WSH_P2SH: b'\x02\x42\x85\xb5'  # Uprv
    },
    'extended_pub': {
        # https://github.com/spesmilo/electrum-docs/blob/master/xpub_version_bytes.rst
        ADDRESS.P2PKH: b'\x04\x35\x87\xcf',  # tpub
        ADDRESS.P2WPKH: b'\x04\x5f\x1c\xf6',  # vpub
        ADDRESS.P2WSH: b'\x02\x57\x54\x83',  # Vpub
        ADDRESS.P2WPKH_P2SH: b'\x04\x4a\x52\x62',  # upub
        ADDRESS.P2WSH_P2SH: b'\x02\x42\x89\xef'  # Upub
    },
    'utxo_url': 'https://testnet.blockchain.info/unspent?active={address}',
    'rawtx_url': 'https://blockstream.info/testnet/api/tx/{txid}/hex',
    'broadcast_url': 'https://testnet.blockchain.info/pushtx'
}

networks = {
    NETWORK.MAIN: main,
    NETWORK.TEST: test
}


def network(attr):
    net = networks[current_network()]
    return net[attr]
