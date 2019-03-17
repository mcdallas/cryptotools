from copy import deepcopy, copy
from collections import deque
from time import sleep

from transformations import bytes_to_int, bytes_to_hex, hex_to_bytes, sha256
from message import is_signature
from btctools.opcodes import SIGHASH, TX, OP
from btctools.network import network
from btctools.script import VM, asm, witness_program, push, pad, ScriptValidationError, var_int, serialize, depush, get_type, decode_scriptpubkey
from btctools.error import ValidationError, SerializationError, SigningError, UpstreamError, HTTPError
from ECDSA.secp256k1 import is_pubkey


concat = b''.join


class Input:
    def __init__(self, output, index, script, sequence=b'\xff\xff\xff\xff', witness=None, referenced_tx=None):
        # Parameters should be bytes as transmitted i.e reversed
        assert isinstance(output, bytes) and len(output) == 32
        self.output = output[::-1]  # referenced tx hash
        self.index = index if isinstance(index, int) else bytes_to_int(index[::-1])
        assert self.index <= 0xffffffff
        self.script = script
        self.sequence = sequence[::-1]
        self._referenced_tx = referenced_tx
        self._referenced_output = None
        self.witness = witness
        self._parent = None
        self.tx_index = None  # index of this input in it's parent tx
        self.parent_id = None

    def ref(self):
        """The output that this input is spending"""
        if self._referenced_output is not None:
            return self._referenced_output
        if self._referenced_tx is None or self._referenced_tx.txid()[::-1] != self.output:
            # Gets the transaction from blockchain.info and caches the result
            self._referenced_tx = Transaction.get(self.output)
        return self._referenced_tx.outputs[self.index]

    @property
    def segwit(self):
        return bool(self.witness)

    @property
    def sequence(self):
        return bytes_to_int(self._sequence)

    @sequence.setter
    def sequence(self, x):
        self._sequence = pad(x, 4)

    @property
    def index(self):
        return bytes_to_int(self._index)

    @index.setter
    def index(self, x):
        self._index = pad(x, 4)

    def serialize(self):
        return self.output[::-1] + self._index[::-1] + serialize(self.script) + self._sequence[::-1]

    def serialize_witness(self):
        if not self.segwit:
            return b'\x00'
        result = var_int(len(self.witness))
        for stack_item in self.witness:
            result += serialize(stack_item)
        return result

    def outpoint(self):
        return self.output[::-1] + self._index[::-1]

    def is_nested(self):
        if self.ref().type() == TX.P2SH:
            try:
                witness_script = witness_program(depush(self.script))
            except ScriptValidationError:
                return False
            if len(witness_script) == 20:
                return TX.P2WPKH
            elif len(witness_script) == 32:
                return TX.P2WSH
        return False

    def type(self):
        referenced_output_type = self.ref().type()
        my_type = str(referenced_output_type.value)
        nested = self.is_nested()
        if nested:
            my_type += f"-{nested.value}"
        return my_type

    def scriptcode(self):
        output = self.ref()
        output_type = self.ref().type()
        if output_type == TX.P2WPKH:
            return OP.DUP.byte + OP.HASH160.byte + push(witness_program(output.script)) + OP.EQUALVERIFY.byte + OP.CHECKSIG.byte
        elif output_type == TX.P2SH:
            if self.is_nested() == TX.P2WPKH:
                return OP.DUP.byte + OP.HASH160.byte + push(witness_program(self.script[1:])) + OP.EQUALVERIFY.byte + OP.CHECKSIG.byte
            elif self.is_nested() == TX.P2WSH:
                return self.witness[-1]
        # elif output_type == TX.P2WPKH:
        #     return output.script
        # elif output_type == TX.P2SH:
        #     return self.script
        elif output_type == TX.P2WSH:
            return self.witness[-1]
        else:
            raise ScriptValidationError(f"No scriptcode for {output_type}")

    # @classmethod
    # def deserialize(cls, bts):
    #     output, index, script_len = bts[:32], bts[32:36], bts[36:37]
    #     script_end = 37 + bytes_to_int(script_len)
    #     script, sequence = bts[37:script_end], bts[script_end:]
    #     assert len(sequence) == 4, 'Invalid input format'
    #     return cls(output=output, index=index, script=script, sequence=sequence)

    @property
    def parent(self):
        if not self._parent:
            if self.parent_id:
                self._parent = Transaction.get(self.parent_id)
            else:
                raise AttributeError('No reference to parent tx')
        return self._parent

    def __repr__(self):
        return f"{self.__class__.__name__}(from={bytes_to_hex(self.output)}, index={self.index})"

    def asm(self):
        return asm(self.script)

    def sign(self, private, hashcode=SIGHASH.ALL):
        output_type = self.ref().type()
        if self.is_signed():
            raise SigningError('Input already signed')
        try:
            tx = self.parent
            idx = self.tx_index
            assert idx is not None
        except (AttributeError, AssertionError):
            raise SigningError("Reference to parent transaction missing")

        sighash = tx.sighash(idx, hashcode=hashcode)
        sig = private.sign_hash(sighash)

        # # https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki#low_s
        # if sig.s > CURVE.N//2:
        #     sig.s = CURVE.N - sig.s

        raw_sig = sig.encode() + hashcode.byte
        if output_type == TX.P2PKH:
            pub = private.to_public().encode(compressed=False)
            self.clear()
            self.script = push(raw_sig) + push(pub)
        elif output_type == TX.P2WPKH:
            pub = private.to_public().encode(compressed=True)
            self.clear()
            self.witness = (raw_sig, pub)
        elif output_type == TX.P2PK:
            self.clear()
            self.script = push(raw_sig)
        else:
            raise SigningError('Cannot sign P2SH or P2WSH outputs.')

    def is_signed(self) -> bool:
        output_type = self.ref().type()
        nested = self.is_nested()
        if output_type == TX.P2PKH:
            try:
                sig, pub = self.asm().split(' ')
            except ValueError:
                return False
            return is_signature(sig[:-2]) and is_pubkey(pub)
        elif output_type == TX.P2WPKH or nested == TX.P2WPKH:
            try:
                return is_signature(self.witness[0][:-1])  # and is_pubkey(self.witness[-1])
            except ScriptValidationError:
                return False
        elif output_type == TX.P2WSH or nested == TX.P2WSH:
            return any(is_signature(bytes_to_hex(item)[:-2]) for item in self.witness)
        elif output_type == TX.P2SH:
            return any((is_signature(item[:-2]) for item in self.asm().split(' ')))
        elif output_type == TX.P2PK:
            return is_signature(self.asm()[:-2])

    def clear(self):
        self.script = b''
        self.witness = tuple()

    def json(self):
        result = {
            "txid": bytes_to_hex(self.output),
            "vout": self.index,
            "scriptSig": {
                "hex": bytes_to_hex(self.script)
            }
        }
        if self.segwit:
            result['witness'] = [bytes_to_hex(wit) for wit in self.witness]
        result["sequence"] = self.sequence
        return result


class Output:

    def __init__(self, value, script):
        # Parameters should be bytes as transmitted i.e reversed
        if isinstance(value, bytes):
            assert len(value) == 8
            self.value = value[::-1]
        else:
            self.value = value

        self.script = script
        self.parent_id = None
        self._parent = None
        self.tx_index = None  # index of this output in it's parent tx

    @property
    def value(self):
        return bytes_to_int(self._value)

    @value.setter
    def value(self, x):
        self._value = pad(x, 8)

    def serialize(self):
        return self._value[::-1] + serialize(self.script)

    @property
    def parent(self):
        if not self._parent:
            if self.parent_id:
                self._parent = Transaction.get(self.parent_id)
            else:
                raise AttributeError('No reference to parent tx')
        return self._parent

    # @classmethod
    # def deserialize(cls, bts):
    #     value, script_len = bts[:8], bts[8:9]
    #     script_end = 9 + bytes_to_int(script_len)
    #     script, rest = bts[9:script_end], bts[script_end:]
    #     assert not rest, 'Invalid output format'
    #     return cls(value=value, script=script)

    def asm(self):
        return asm(self.script)

    def type(self):
        return get_type(self.script)

    def spend(self):
        """Creates an empty input that spends this output"""
        if self.tx_index is not None:
            if isinstance(self.parent, Transaction):
                inp = Input(output=self.parent.txid(), index=self.tx_index, script=b'')
                inp._referenced_output = self
                return inp
            elif self.parent_id is not None:
                inp = Input(output=self.parent_id, index=self.tx_index, script=b'')
                inp._referenced_output = self
                return inp
        raise AttributeError('This output has no reference to its parent tx. Set the attribute first or use the Output.get constructor')

    @staticmethod
    def get(txid, i):
        tx = Transaction.get(txid)
        out = tx.outputs[i]
        out._parent = tx
        out.tx_index = i
        return out

    def __repr__(self):
        return f"{self.__class__.__name__}(type={self.type().value}, value={self.value/10**8} BTC)"

    def json(self, index=None):
        data = {
            "value": self.value/10**8,
        }
        if index:
            data["n"] = index
        data["scriptPubKey"] = decode_scriptpubkey(self.script)
        return data


class Transaction:
    _network = None

    def __init__(self, inputs, outputs, version=b'\x01\x00\x00\x00', lock_time=b'\x00\x00\x00\x00', _network=None):
        self.inputs = inputs
        self.outputs = outputs
        assert len(version) == 4, 'Invalid Version'
        assert len(lock_time) == 4, 'Invalid lock time'
        self._version = version[::-1]
        self.version = bytes_to_int(self._version)
        self._lock_time = lock_time[::-1]
        self.lock_time = bytes_to_int(self._lock_time)

        self._network = _network

    def __len__(self):
        return len(self.serialize())

    @property
    def segwit(self):
        """https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#specification"""
        return any((inp.segwit for inp in self.inputs))

    def serialize(self, segwit=None):
        if segwit is None:
            segwit = self.segwit
        inputs = concat((inp.serialize() for inp in self.inputs))
        outputs = concat((out.serialize() for out in self.outputs))
        if not segwit:
            return self._version[::-1] + var_int(len(self.inputs)) + inputs + var_int(len(self.outputs)) + outputs + self._lock_time[::-1]
        witness = concat((inp.serialize_witness() for inp in self.inputs))
        return self._version[::-1] + b'\x00\x01' + var_int(len(self.inputs)) + inputs + var_int(len(self.outputs)) + outputs + witness + self._lock_time[::-1]

    @classmethod
    def deserialize(cls, tx: bytes) -> 'Transaction':
        original_tx = copy(tx)
        try:
            return cls._deserialize(tx)
        except AssertionError as e:
            raise SerializationError(str(e), data=original_tx) from None

    @classmethod
    def _deserialize(cls, tx: bytes) -> 'Transaction':
        segwit = False
        tx = deque(tx)

        def pop(x):
            data = []
            for _ in range(x):
                data.append(tx.popleft())
            return bytes(data)

        def read_var_int():
            """https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer"""
            byte = pop(1)
            if byte == b'\xfd':
                result = pop(2)
            elif byte == b'\xfe':
                result = pop(4)
            elif byte == b'\xff':
                result = pop(8)
            else:
                result = byte
            return bytes_to_int(result[::-1])

        version = pop(4)
        input_count = read_var_int()
        if input_count == 0x00:
            segwit = True

            flag = pop(1)
            assert flag == b'\x01'
            input_count = read_var_int()

        inputs, outputs, witnesses = [], [], []

        for _ in range(input_count):
            tx_hash = pop(32)
            index = pop(4)
            script_len = read_var_int()
            script = pop(script_len)
            sequence = pop(4)

            inp = Input(output=tx_hash, index=index, script=script, sequence=sequence, witness=None)
            inputs.append(inp)

        output_count = read_var_int()

        for _ in range(output_count):
            value = pop(8)
            script_len = read_var_int()
            script = pop(script_len)

            out = Output(value=value, script=script)
            outputs.append(out)

        if segwit:
            for inp in inputs:
                len_witness = read_var_int()

                elements = []
                for _ in range(len_witness):
                    element_len = read_var_int()
                    element = pop(element_len)
                    elements.append(element)

                if elements:
                    inp.witness = tuple(elements)

        lock_time = pop(4)
        assert not tx, f"{len(tx)} Leftover bytes"
        transaction = cls(inputs=inputs, outputs=outputs, version=version, lock_time=lock_time)
        # Set references
        for idx, out in enumerate(transaction.outputs):
            out._parent = transaction
            out.tx_index = idx
        for idx, inp in enumerate(transaction.inputs):
            inp._parent = transaction
            inp.tx_index = idx
        return transaction

    def __repr__(self):
        return f"{self.__class__.__name__}(inputs={len(self.inputs)}, outputs={len(self.outputs)})"

    def txid(self):
        return sha256(sha256(self.serialize(segwit=False)))

    def wtxid(self):
        if not self.segwit:
            return self.txid()
        return sha256(sha256(self.serialize(segwit=True)))

    def json(self):
        return {
            "txid": bytes_to_hex(self.txid()[::-1]),  # TODO
            "version": self.version,
            "size": len(self.serialize()),
            "locktime": self.lock_time,
            "vin": [inp.json() for inp in self.inputs],
            "vout": [out.json(i) for i, out in enumerate(self.outputs)]
        }

    def hex(self):
        return bytes_to_hex(self.serialize())

    @classmethod
    def from_hex(cls, hexstring):
        return cls.deserialize(hex_to_bytes(hexstring))

    @classmethod
    def get(cls, txhash, _network=None):
        """Construct a transaction from it's tx id by getting the raw data from blockchain.info"""
        import urllib.request
        from urllib.error import HTTPError
        if isinstance(txhash, bytes):
            txhash = bytes_to_hex(txhash)

        url = network('rawtx_url', _network).format(txid=txhash)
        req = urllib.request.Request(url)
        sleep(0.1)
        try:
            with urllib.request.urlopen(req) as resp:
                try:
                    return cls.from_hex(resp.read().decode())
                except SerializationError as e:
                    e.txhash = txhash
                    raise e
        except HTTPError as e:
            resp = e.read().decode()
            raise UpstreamError(resp)

    def sighash(self, i, script=b'', hashcode=SIGHASH.ALL):
        inp = self.inputs[i]
        tx_type = inp.ref().type()

        if tx_type in (TX.P2PK, TX.P2PKH) or (tx_type == TX.P2SH and not inp.is_nested()):
            preimage = self.signature_form_legacy(i=i, script=script, hashcode=hashcode)
        else:
            preimage = self.signature_form_segwit(i=i, hashcode=hashcode)

        return sha256(sha256(preimage))

    def signature_form_legacy(self, i, script=b'', hashcode=SIGHASH.ALL):
        """Create the object to be signed for the i-th input of this transaction"""
        # Recreates the object that needs to be signed which is not the actual transaction
        # More info at:
        # https://bitcoin.stackexchange.com/questions/32628/redeeming-a-raw-transaction-step-by-step-example-required/32695#32695
        # https://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx
        # https://rya.nc/sartre.html
        # https://bitcoin.stackexchange.com/questions/41209/how-to-sign-a-transaction-with-multiple-inputs
        # https://en.bitcoin.it/wiki/OP_CHECKSIG
        tx = deepcopy(self)

        # the input references a previous output from which we need the scriptPubKey
        script = script or tx.inputs[i].ref().script

        for input in tx.inputs:
            input.script = b''

        tx.inputs[i].script = script

        # https://en.bitcoin.it/wiki/OP_CHECKSIG
        if hashcode == SIGHASH.NONE:
            tx.outputs = []
        elif hashcode == SIGHASH.SINGLE:
            tx.outputs = tx.outputs[:len(tx.inputs)]
            for output in tx.outputs:
                output.script = b''
                output.value = 2**64 - 1
            for idx, input in enumerate(tx.inputs):
                if not idx == i:
                    input.sequence = 0
        elif hashcode == SIGHASH.ANYONECANPAY:
            tx.inputs = [tx.inputs[i]]

        return tx.serialize(segwit=tx.inputs[i].segwit) + pad(hashcode.value, 4)[::-1]

    def signature_form_segwit(self, i, hashcode=SIGHASH.ALL):
        """Segwit version of signature_form"""
        # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
        tx = deepcopy(self)

        ref = tx.inputs[i].ref()

        nversion = tx._version[::-1]
        hashprevouts = sha256(sha256(concat((inp.outpoint() for inp in tx.inputs)))) if not hashcode.is_anyonecanpay() else pad(0, 32)
        hashsequence = sha256(sha256(concat(inp._sequence[::-1] for inp in tx.inputs))) if hashcode == SIGHASH.ALL else pad(0, 32)
        outpoint = tx.inputs[i].outpoint()
        scriptcode = serialize(tx.inputs[i].scriptcode())
        value = ref._value[::-1]
        nsequence = tx.inputs[i]._sequence[::-1]

        if not (hashcode.is_single() or hashcode.is_none()):
            hashoutputs = sha256(sha256(concat(out._value[::-1] + push(out.script) for out in tx.outputs)))
        elif hashcode.is_single() and i < len(tx.outputs):
            hashoutputs = sha256(sha256(tx.outputs[i]._value[::-1] + push(tx.outputs[i].script)))
        else:
            hashoutputs = pad(0, 32)

        nlocktime = tx._lock_time[::-1]
        sighash = pad(hashcode.value, 4)[::-1]

        return concat([nversion, hashprevouts, hashsequence, outpoint, scriptcode, value, nsequence, hashoutputs, nlocktime, sighash])

    def sign(self, private, hashcode=SIGHASH.ALL):
        for inp in self.inputs:
            if inp.ref().type() not in (TX.P2SH, TX.P2WSH):
                inp.sign(private=private, hashcode=hashcode)

    def verify(self, i=None, debug=False):
        """Run the script for the i-th input or all the inputs"""
        sum_inputs = sum(inp.ref().value for inp in self.inputs)
        sum_outputs = sum(out.value for out in self.outputs)
        if sum_outputs > sum_inputs:
            raise ValidationError("Value of outputs is greater than value of inputs")
        if i is not None:
            vm = VM(self, i)
            return vm.verify(debug=debug)
        else:
            results = []
            for idx in range(len(self.inputs)):
                vm = VM(self, idx)
                results.append(vm.verify())

            return all(results)

    def broadcast(self):
        import urllib.request
        import urllib.parse

        url = network('broadcast_url', self._network)
        payload = {'tx': self.hex()}
        data = urllib.parse.urlencode(payload).encode('ascii')
        req = urllib.request.Request(url, data)

        try:
            with urllib.request.urlopen(req) as response:
                resp = response.read()
        except HTTPError as e:
            resp = e.read()
        return resp.decode().strip('\n')
