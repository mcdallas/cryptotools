from functools import partial
from copy import copy, deepcopy
from ECDS.secp256k1 import PublicKey
from message import Signature
from transformations import bytes_to_int, int_to_bytes, bytes_to_hex, hex_to_bytes, hash160, sha256
from btctools.opcodes import OP, SIGHASH, TX


def op_push(i: int) -> bytes:
    """https://en.bitcoin.it/wiki/Script#Constants"""
    if i < 0x4c:
        return int_to_bytes(i)
    elif i < 0xff:
        return b'\x4c' + int_to_bytes(i)
    elif i < 0xffff:
        return b'\x4d' + int_to_bytes(i)
    else:
        return b'\x4e' + int_to_bytes(i)


def push(script: bytes) -> bytes:
    return op_push(len(script)) + script


def witness_byte(witver: int) -> bytes:
    assert 0 <= witver <= 16, "Witness version must be between 0-16"
    return int_to_bytes(witver + 0x50 if witver > 0 else 0)


def asm(script):
    """Turns a script into a symbolic representation"""
    if isinstance(script, str):
        script = hex_to_bytes(script)
    else:
        script = copy(script)

    def read(n):
        nonlocal script
        data = script[:n]
        assert data or n == 0, 'EOF'
        script = script[n:]
        return data

    results = []
    while script:
        byte = bytes_to_int(read(1))
        op = OP(byte)
        if byte in range(1, 76):
            results.append(bytes_to_hex(read(byte)))
        else:
            results.append(str(op))

    return ' '.join(results)


class OperationFailure(Exception):
    pass


class InvalidTransaction(Exception):
    pass


class VM:
    """An environment to run the scripts"""

    def __init__(self, tx, index):
        self.tx = tx
        self.index = index
        self.input = tx.inputs[index]
        self.scriptPubKey = self.input.ref().script
        self.scriptSig = self.input.script
        self.script = self.scriptSig + self.scriptPubKey
        self.stack = []
        self.OPS = {OP(i): partial(self.OP_PUSH, i) for i in range(1, 76)}
        self.OPS.update({OP(i): lambda: self.push(int_to_bytes(i-80)) for i in range(81, 97)})

    def read(self, n):
        """Read and remove first n bytes from the script"""
        data = self.script[:n]
        if not data:
            raise OperationFailure('EOF')
        self.script = self.script[n:]
        return data

    def asm(self):
        return asm(self.script)

    def pop(self):
        """Pop top item from the stack"""
        return self.stack.pop()

    def push(self, item):
        """Push item to the top of the stack"""
        self.stack.append(item)

    def op(self, opcode):
        """Execute an OPCODE (if implemented)."""
        # Input is an OP enum value
        operation = self.OPS.get(opcode) or getattr(self, str(opcode), None)  # look to self.OPS first and then in object methods
        if not operation:
            raise NotImplementedError(str(opcode))
        else:
            operation()

    def step(self):
        """Executes one script operation"""
        byte = bytes_to_int(self.read(1))
        opcode = OP(byte)
        self.op(opcode)

    def verify(self):
        tx_type = self.input.ref().type()
        if tx_type == TX.P2PKH:
            return self.verify_p2pkh()
        elif tx_type == TX.P2SH:
            return self.verify_p2sh()
        else:
            raise InvalidTransaction

    def verify_p2pkh(self):
        while self.script:
            self.step()
        return self.pop() is True

    def verify_p2sh(self):
        self.step()
        self.step()
        self.step()

        state = VM(self.tx, self.index)
        state.stack = deepcopy(self.stack)
        state.script = state.pop()

        first_verification = self.verify_p2pkh()
        if first_verification is False:
            return False

        return state.verify_p2pkh()

    def OP_PUSH(self, n):
        """Push the next n bytes to the top of the stack"""
        self.push(self.read(n))

    def OP_DUP(self):
        """	Duplicates the top stack item."""
        self.push(copy(self.stack[-1]))

    def OP_NIP(self):
        """	Removes the second-to-top stack item."""
        temp = self.pop()
        self.pop()
        self.push(temp)

    def OP_NOP(self):
        """ Does Nothing."""
        pass

    def OP_HASH160(self):
        """ The input is hashed twice: first with SHA-256 and then with RIPEMD-160."""
        item = self.pop()
        self.push(hash160(item))

    def OP_EQUAL(self):
        """Returns 1 if the inputs are exactly equal, 0 otherwise"""
        item1, item2 = self.pop(), self.pop()
        self.push(item1 == item2)

    def OP_VERIFY(self):
        """Marks transaction as invalid if top stack value is not true. The top stack value is removed."""
        if not self.pop() is True:
            raise InvalidTransaction

    def OP_EQUALVERIFY(self):
        """Same as OP_EQUAL, but runs OP_VERIFY afterward."""
        self.op(OP.EQUAL)
        self.op(OP.VERIFY)

    def OP_CHECKSIG(self):
        """https://en.bitcoin.it/wiki/OP_CHECKSIG"""
        pub = PublicKey.decode(self.pop())
        extended_sig = self.pop()
        sig = Signature.decode(extended_sig[:-1])
        hashcode = SIGHASH(extended_sig[-1])

        signed_obj = self.tx.signature_form(i=self.index, hashcode=hashcode)
        hashed = sha256(sha256(signed_obj))
        self.push(sig.verify_hash(hashed, pub))

    def OP_0(self):
        """An empty array of bytes is pushed onto the stack. (This is not a no-op: an item is added to the stack.)"""
        self.push(b'')
