from transformations import int_to_bytes, bytes_to_int, bytes_to_hex, hex_to_bytes, sha256
from btctools.opcodes import SIGHASH, VM
from copy import deepcopy


def pad(val, bytelength):
    if isinstance(val, bytes):
        assert len(val) == bytelength, f"Value should be {bytelength} bytes long"
        return val
    elif isinstance(val, int):
        return int_to_bytes(val).rjust(bytelength, b'\x00')
    else:
        raise TypeError('Value should be bytes or int')


class Input:
    def __init__(self, output, index, script, sequence=b'\xff\xff\xff\xff', referenced_tx=None):
        # parameters should be bytes as transmitted i.e reversed
        assert isinstance(output, bytes) and len(output) == 32
        self.output = output[::-1]  # referenced tx hash
        self.index = index[::-1] if isinstance(index, int) else bytes_to_int(index[::-1])
        assert self.index <= 0xffffffff
        self.script = script
        self.sequence = sequence
        self._referenced_tx = referenced_tx

    def ref(self):
        """The output that this input is spending"""
        if self._referenced_tx is None or self._referenced_tx.txid() != self.output:
            # Gets the transaction from bitcoin.info and caches the result
            self._referenced_tx = Transaction.get(self.output)
        return self._referenced_tx.outputs[self.index]

    @property
    def script_length(self):
        return int_to_bytes(len(self.script))

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
        return self.output[::-1] + self._index[::-1] + self.script_length + self.script + self._sequence

    @classmethod
    def deserialize(cls, bts):
        output, index, script_len = bts[:32], bts[32:36], bts[36:37]
        script_end = 37 + bytes_to_int(script_len)
        script, sequence = bts[37:script_end], bts[script_end:]
        assert len(sequence) == 4, 'Invalid input format'
        return cls(output=output, index=index, script=script, sequence=sequence)

    def __repr__(self):
        return f"{self.__class__.__name__}(from={bytes_to_hex(self.output)})"

    def json(self):
        return {
            "txid": bytes_to_hex(self.output),
            "vout": self.index,
            "scriptSig": {
                "hex": bytes_to_hex(self.script)
            },
            "sequence": self.sequence
        }


class Output:

    def __init__(self, value, script):
        if isinstance(value, bytes):
            assert len(value) == 8
            self.value = value[::-1]
        else:
            self.value = value

        self.script = script

    @property
    def value(self):
        return bytes_to_int(self._value)

    @value.setter
    def value(self, x):
        self._value = pad(x, 8)

    @property
    def script_len(self):
        return len(self.script)

    def serialize(self):
        return self._value[::-1] + int_to_bytes(self.script_len) + self.script

    @classmethod
    def deserialize(cls, bts):
        value, script_len = bts[:8], bts[8:9]
        script_end = 9 + bytes_to_int(script_len)
        script, rest = bts[9:script_end], bts[script_end:]
        assert not rest, 'Invalid output format'
        return cls(value=value, script=script)

    def __repr__(self):
        return f"{self.__class__.__name__}(value={self.value/10**8} BTC)"

    def json(self, index=None):
        data = {
            "value": self.value/10**8,
        }
        if index:
            data["n"] = index
        data["scriptPubKey"] = {"hex": bytes_to_hex(self.script)}
        return data


class Transaction:

    def __init__(self, inputs, outputs, version=b'\x01\x00\x00\x00', lock_time=b'\x00\x00\x00\x00'):
        assert len(inputs) <= 0xff, 'Too many inputs'
        self.inputs = inputs
        assert len(outputs) <= 0xff, 'Too many outputs'
        self.outputs = outputs
        assert len(version) == 4, 'Invalid Version'
        assert len(lock_time) == 4, 'Invalid lock time'
        self._version = version[::-1]
        self.version = bytes_to_int(self._version)
        self._lock_time = lock_time[::-1]
        self.lock_time = bytes_to_int(self._lock_time)

    def serialize(self):
        inputs = b''.join((inp.serialize() for inp in self.inputs))
        outputs = b''.join((out.serialize() for out in self.outputs))
        return self._version[::-1] + int_to_bytes(len(self.inputs)) + inputs + int_to_bytes(len(self.outputs)) + outputs + self._lock_time[::-1]

    @classmethod
    def deserialize(cls, tx: bytes) -> 'Transaction':
        def pop(x):
            nonlocal tx
            data = tx[:x]
            assert data, 'EOF'
            tx = tx[x:]
            return data

        def var_int():
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
        input_count = var_int()
        inputs, outputs = [], []

        while input_count:
            tx_hash = pop(32)
            index = pop(4)
            script_len = var_int()
            script = pop(script_len)
            sequence = pop(4)

            inp = Input(output=tx_hash, index=index, script=script, sequence=sequence)
            inputs.append(inp)

            input_count -= 1

        output_count = bytes_to_int(pop(1))

        while output_count:
            value = pop(8)
            script_len = var_int()
            script = pop(script_len)

            out = Output(value=value, script=script)
            outputs.append(out)
            output_count -= 1

        lock_time = pop(4)
        assert not tx, 'Leftover bytes'
        return cls(inputs=inputs, outputs=outputs, version=version, lock_time=lock_time)

    def __repr__(self):
        return f"{self.__class__.__name__}(inputs={len(self.inputs)}, outputs={len(self.outputs)})"

    def txid(self):
        return sha256(sha256(self.serialize()))

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
    def get(cls, txhash):
        import urllib.request
        if isinstance(txhash, bytes):
            txhash = bytes_to_hex(txhash)
        url = f"https://blockchain.info/rawtx/{txhash}?format=hex"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            assert 200 <= resp.status < 300, f"{resp.status}: {resp.reason}"
            return cls.from_hex(resp.read().decode())

    def signature_form(self, i, script=None, hashcode=SIGHASH.ALL):
        """Create the object to be signed for the i-th input of this transaction"""
        # We need to recreate the object that needs to be signed which is not the actual transaction
        # More info at:
        # https://bitcoin.stackexchange.com/questions/32628/redeeming-a-raw-transaction-step-by-step-example-required/32695#32695
        # https://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx
        # https://rya.nc/sartre.html
        # https://bitcoin.stackexchange.com/questions/41209/how-to-sign-a-transaction-with-multiple-inputs
        # https://en.bitcoin.it/wiki/OP_CHECKSIG
        tx = deepcopy(self)

        # the input references a previous output from which we need the scriptPubKey
        # if it was not provided get it from blockchain.info
        if script is None:
            script = tx.inputs[i].ref().script

        for input in tx.inputs:
            input.script = b''

        tx.inputs[i].script = script

        # https://en.bitcoin.it/wiki/OP_CHECKSIG
        if hashcode == SIGHASH.NONE:
            tx.outputs = []
        elif hashcode == SIGHASH.SIGNLE:
            tx.outputs = tx.outputs[:len(tx.inputs)]
            for output in tx.outputs:
                output.script = b''
                output.value = 2**64 - 1
            for idx, input in enumerate(tx.inputs):
                if not idx == i:
                    input.sequence = 0
        elif hashcode == SIGHASH.ANYONECANPAY:
            tx.inputs = [tx.inputs[i]]

        return tx.serialize() + pad(hashcode.value, 4)[::-1]

    def verify(self, i=None):
        """Run the script for the i-th input or all the inputs"""
        if i is not None:
            vm = VM(self, i)
            return vm.verify()
        else:
            results = []
            for idx in range(len(self.inputs)):
                vm = VM(self, idx)
                results.append(vm.verify())

            return all(results)

