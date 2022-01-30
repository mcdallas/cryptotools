import os
import json
import base64
import pathlib
from enum import Enum
from typing import List
from urllib import request, parse
from urllib.error import HTTPError

import cryptotools
from cryptotools.BTC.error import UpstreamError, BackendError, NotSupportedError
from cryptotools.BTC.network import NETWORK, current_network
from cryptotools.transformations import hex_to_bytes, btc_to_satoshi


class Backend:
    """An interface for communicating with the Bitcoin network"""

    def get_tx(self, txhash: str) -> str:
        raise NotImplementedError

    def broadcast(self, rawtx: str) -> bool:
        raise NotImplementedError

    def get_utxos(self, address: str) -> List['Output']:
        raise NotImplementedError

class BlockchainInfo(Backend):
    """Pulls information from the blockchain.info API"""

    UTXO_URLS = {
        NETWORK.MAIN: 'https://blockchain.info/unspent?active={address}',
        NETWORK.TEST: 'https://testnet.blockchain.info/unspent?active={address}'
    }
    BROADCAST_URLS = {
        NETWORK.MAIN: 'https://blockchain.info/pushtx',
        NETWORK.TEST: 'https://testnet.blockchain.info/pushtx'
    }
    RAW_TX_URLS = {
        NETWORK.MAIN: 'https://blockchain.info/rawtx/{txid}?format=hex',
        NETWORK.TEST: 'https://blockstream.info/testnet/api/tx/{txid}/hex'
    }

    def _get_url(self, url_map):
        network = current_network()
        try:
            return url_map[network]
        except KeyError:
            raise NotSupportedError(f"The {self.__class__.__name__} backend does not support this functionality for the network {network}")

    def get_utxos(self, address):
        from cryptotools.BTC.transaction import Output

        url = self._get_url(self.UTXO_URLS)
        req = request.Request(url.format(address=address))
        outputs = []
        try:
            with request.urlopen(req) as resp:
                data = json.loads(resp.read().decode())
        except HTTPError as e:
            resp = e.read().decode()
            if resp == 'No free outputs to spend':
                return []
            else:
                raise UpstreamError(resp)
        else:
            for item in data['unspent_outputs']:
                out = Output(value=item['value'], script=hex_to_bytes(item['script']))
                out.parent_id = hex_to_bytes(item['tx_hash_big_endian'])
                out.tx_index = item['tx_output_n']
                outputs.append(out)
            return outputs
    
    def get_tx(self, txid):
        url = self._get_url(self.RAW_TX_URLS)
        req = request.Request(url.format(txid=txid))
        
        try:
            with request.urlopen(req) as resp:
                return resp.read().decode()
        except HTTPError as e:
            resp = e.read().decode()
            raise UpstreamError(resp)

    def broadcast(self, rawtx: str):

        url = self._get_url(self.BROADCAST_URLS)

        payload = {'tx': rawtx}
        data = parse.urlencode(payload).encode('ascii')
        req = request.Request(url, data)

        try:
            with request.urlopen(req) as response:
                resp = response.read()
        except HTTPError as e:
            resp = e.read()
        
        return resp.decode().strip('\n') == 'Transaction Submitted'

class RPC(Backend):
    """Pulls information from a Bitcoin Core full node"""

    HOST = os.environ.get('CRYPTOTOOLS_RPC_HOST', '127.0.0.1')
    PORT = int(os.environ.get('CRYPTOTOOLS_RPC_PORT', 8332))
    USER = os.environ.get('CRYPTOTOOLS_RPC_USER')
    PW = os.environ.get('CRYPTOTOOLS_RPC_PW')

    def __init__(self):
        self.url  = f'http://{self.HOST}:{self.PORT}'
        self.headers = {"content-type": "application/json"}
        if self.USER and self.PW:
            auth = base64.b64encode(f'{self.USER}:{self.PW}'.encode())
            self.headers["Authorization"] = f"Basic {auth.decode()}"

        self._check_if_correct_network()

    def _check_if_correct_network(self):
        info = self.get_blockchain_info()
        network_name = info['chain']

        bitcoin_node_network = {
            'main': NETWORK.MAIN,
            'test': NETWORK.TEST
        }[network_name]
        network = current_network()

        if network != bitcoin_node_network:
            raise BackendError(f"Configured network is {network} but the Bitcoin node is running on {bitcoin_node_network}")

    def rpc_call(self, method: str, params: list = None):
        payload = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
            }

        data = json.dumps(payload).encode()
        req = request.Request(self.url, data=data, headers=self.headers)
        try:
            with request.urlopen(req) as resp:
                return json.loads(resp.read().decode())
        except HTTPError as e:
            error = json.loads(e.read().decode())
            raise UpstreamError(error['error']['message'])

    def get_tx(self, txhash):
        return self.rpc_call('getrawtransaction', [txhash])['result']

    def get_utxos(self, address: str) -> List['Output']:
        from cryptotools.BTC.transaction import Output

        response = self.rpc_call('scantxoutset', ['start', [f"addr({address})"]])['result']
        
        if not response['success']:
            raise UpstreamError(response['error'])
        outs = response['unspents']
        outputs = []
        for out in outs:
            sats = btc_to_satoshi(out['amount'])
            outputs.append(Output(value=sats, script=hex_to_bytes(out['scriptPubKey'])))
        return outputs

    def get_blockchain_info(self):
        return self.rpc_call('getblockchaininfo')['result']

    def broadcast(self, rawtx):
        result = self.rpc_call('sendrawtransaction', [rawtx])['result']
        return True

class TestingBackend(Backend):
    """Backend used for testing to avoid network calls"""

    ECHO = False
    ROOT_PATH = pathlib.Path(cryptotools.__path__[0])
    TRANSACTIONS_PATH = ROOT_PATH.parent / 'tests' / 'transactions'
    CACHE = {}

    def get_tx(self, txhash: str) -> str:
        if txhash in self.CACHE:
            if self.ECHO:
                print(f"\nGetting tx {txhash} from cache")
            return self.CACHE[txhash]
        return self._get_tx_from_file(txhash)

    def _get_tx_from_file(self, txhash):
        filepath = self.TRANSACTIONS_PATH / f"{txhash}.txt"
        if self.ECHO:
            print(f"\nGetting tx {txhash} from file")
        
        with open(filepath) as f:
            hexstring = f.read()
            self.CACHE[txhash] = hexstring
            return hexstring



class Backends(Enum):
    BLOCKCHAININFO = 'BLOCKCHAININFO'
    RPC = 'RPC'
    TEST = 'TEST'

    @classmethod
    def from_env(cls):
        env = os.environ.get('CRYPTOTOOLS_BACKEND', 'BLOCKCHAININFO').upper()
        return cls(env)


def current_backend():
    backend_type = Backends.from_env()

    backend =  {
        Backends.BLOCKCHAININFO: BlockchainInfo,
        Backends.RPC: RPC,
        Backends.TEST: TestingBackend
    }[backend_type]

    return backend()