from transformations import *
from hashlib import sha256


class Input:
    def __init__(self, output, index, script, sequence=b'\xff\xff\xff\xff'):
        assert isinstance(output, bytes) and len(output) == 32
        self.output = output[::-1]
        self.index = index if isinstance(index, int) else bytes_to_int(index)
        assert self.index <= 0xffffffff
        self.script = script
        self.script_length = int_to_bytes(len(script))
        self.sequence = sequence

    def serialize(self):
        return self.output[::-1] + int_to_bytes(self.index).ljust(4, b'\x00') + self.script_length + self.script + self.sequence

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
            "sequence": bytes_to_int(self.sequence)
        }


class Output:

    def __init__(self, value, script):
        if isinstance(value, bytes):
            assert len(value) == 8
            self.value = bytes_to_int(value[::-1])
        elif isinstance(value, int):
            self.value = value
        else:
            raise AssertionError('Value should be bytes or int')

        self.script = script
        self.script_len = len(script)

    def serialize(self):
        return int_to_bytes(self.value).rjust(8, b'\x00')[::-1] + int_to_bytes(self.script_len) + self.script

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
        self.version = version[::-1]  # inversed
        self.lock_time = lock_time[::-1]

    def serialize(self):
        inputs = b''.join((inp.serialize() for inp in self.inputs))
        outputs = b''.join((out.serialize() for out in self.outputs))
        return self.version[::-1] + int_to_bytes(len(self.inputs)) + inputs + int_to_bytes(len(self.outputs)) + outputs + self.lock_time[::-1]

    @classmethod
    def deserialize(cls, tx: bytes) -> 'Transaction':
        def pop(x):
            nonlocal tx
            data = tx[:x]
            assert data, 'EOF'
            tx = tx[x:]
            return data

        version = pop(4)
        input_count = bytes_to_int(pop(1))
        inputs, outputs = [], []

        while input_count:
            tx_hash = pop(32)
            index = pop(4)
            script_len = bytes_to_int(pop(1))
            script = pop(script_len)
            sequence = pop(4)

            inp = Input(output=tx_hash, index=index, script=script, sequence=sequence)
            inputs.append(inp)

            input_count -= 1

        output_count = bytes_to_int(pop(1))

        while output_count:
            value = pop(8)
            script_len = bytes_to_int(pop(1))
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
        return sha256(sha256(self.serialize()).digest()).digest()

    def json(self):
        return {
            "txid": bytes_to_hex(self.txid()[::-1]),
            "version": bytes_to_int(self.version),
            "size": len(self.serialize()),
            "locktime": bytes_to_int(self.lock_time),
            "vin": [inp.json() for inp in self.inputs],
            "vout": [out.json(i) for i, out in enumerate(self.outputs)]
        }

