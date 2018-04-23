from functools import partial
from copy import copy, deepcopy
from ECDSA.secp256k1 import PublicKey
from message import Signature
from transformations import bytes_to_int, int_to_bytes, bytes_to_hex, hex_to_bytes, hash160, sha256
from btctools.opcodes import OP, SIGHASH, TX
from btctools.error import ScriptValidationError


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


def var_int(n):
    if n < 0xfd:
        return int_to_bytes(n)
    elif n <= 0xffff:
        return b'\xfd' + pad(n, 2)[::-1]
    elif n <= 0xffffffff:
        return b'\xfe' + pad(n, 4)[::-1]
    elif n <= 0xffffffffffffffff:
        return b'\xff' + pad(n, 8)[::-1]
    else:
        raise ValueError('Data too long for var_int')


def serialize(bts):
    return var_int(len(bts)) + bts


def push(script: bytes) -> bytes:
    return op_push(len(script)) + script


def depush(script: bytes) -> bytes:
    if len(script) == 0:
        raise ScriptValidationError('Empty script')
    push_byte, script = script[0], script[1:]
    op = OP(push_byte)
    if push_byte not in range(1, 76):
        raise ScriptValidationError(f'Script does not start with a PUSH opcode: {op}')
    if len(script) < push_byte:
        raise ScriptValidationError('Script too short')
    elif len(script) > push_byte:
        raise ScriptValidationError('Script too long')
    return script


def witness_byte(witver: int) -> bytes:
    assert 0 <= witver <= 16, "Witness version must be between 0-16"
    return int_to_bytes(witver + 0x50 if witver > 0 else 0)


def is_witness_program(script):
    """https://github.com/bitcoin/bitcoin/blob/5961b23898ee7c0af2626c46d5d70e80136578d3/src/script/script.cpp#L221"""
    if len(script) < 4 or len(script) > 42:
        return False
    if script[0] != OP._0.value and (script[0] < OP._1.value or script[0] > OP._16.value):
        return False
    if script[1] < 0x02 or script[1] > 0x28:
        return False
    return True


def witness_program(script):
    if not is_witness_program(script):
        raise ScriptValidationError("Script is not a witness program")
    return script[2:]


def version_byte(script):
    if not is_witness_program(script):
        raise ScriptValidationError("Script is not a witness program")
    return script[0]


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


def pad(val, bytelength):
    if isinstance(val, bytes):
        assert len(val) == bytelength, f"Value should be {bytelength} bytes long"
        return val
    elif isinstance(val, int):
        return int_to_bytes(val).rjust(bytelength, b'\x00')
    else:
        raise TypeError('Value should be bytes or int')


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
        self.output = self.input.ref()
        self.scriptPubKey = self.output.script
        self.scriptSig = self.input.script
        self.script = self.scriptSig + self.scriptPubKey
        self.stack = []
        self.OPS = {OP(i): partial(self.OP_PUSH, i) for i in range(1, 76)}
        self.OPS.update({OP(i): partial(self.push, i-80) for i in range(81, 97)})

    def read(self, n):
        """Read and remove first n bytes from the script"""
        data = self.script[:n]
        if not data:
            raise OperationFailure('EOF')
        self.script = self.script[n:]
        return data

    def asm(self):
        return asm(self.script)

    def print(self):
        print(self.asm())
        print([bytes_to_hex(i) for i in self.stack])

    def pop(self):
        """Pop top item from the stack"""
        try:
            return self.stack.pop()
        except IndexError:
            raise OperationFailure('Popping from empty stack')

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
            try:
                operation()
            except Exception as e:
                raise OperationFailure(e)

    def step(self):
        """Executes one script operation"""
        byte = bytes_to_int(self.read(1))
        opcode = OP(byte)
        self.op(opcode)

    def verify(self, debug=False):
        tx_type = self.input.ref().type()
        if tx_type in (TX.P2PKH, TX.P2PK):
            verifier = self.verify_legacy
        elif tx_type == TX.P2SH:
            verifier = self.verify_p2sh
        elif tx_type == TX.P2WPKH:
            verifier = self.verify_p2wpkh
        elif tx_type == TX.P2WSH:
            verifier = self.verify_p2wsh
        else:
            raise InvalidTransaction(f"Unknown transaction type {tx_type}")
        try:
            return verifier()
        except OperationFailure:
            if not debug:
                return False
            raise

    def verify_legacy(self):
        while self.script:
            self.step()
        return self.pop() is True

    def verify_p2sh(self):
        self.step()

        state = VM(self.tx, self.index)
        state.stack = deepcopy(self.stack)
        redeem = state.pop()  # redeem script

        first_verification = self.verify_legacy()
        if first_verification is False:
            return False

        # determine if it is a normal P2SH or a nested P2WKH/P2WSH into a P2SH
        nested = self.input.is_nested()
        if nested == TX.P2WPKH:
            # version = version_byte(redeem)
            if not self.scriptSig == push(redeem):
                raise InvalidTransaction("The scriptSig must be exactly a push of the BIP16 redeemScript in a P2SH-P2PKH transaction")
            # redeem = witness_program(redeem)
            state.scriptPubKey = redeem
            state.scriptSig = b''

            return state.verify_p2wpkh()
        elif nested == TX.P2WSH:
            state.scriptPubKey = redeem
            state.scriptSig = b''
            return state.verify_p2wsh()

        state.script = redeem
        return state.verify_legacy()

    def verify_p2wpkh(self):
        """https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#witness-program"""
        if not version_byte(self.scriptPubKey) == 0x00:
            raise InvalidTransaction('Unknown witness version')

        if len(self.scriptSig) > 0:
            raise InvalidTransaction(f'ScriptSig must be empty for a {TX.P2WPKH} transaction')

        witness = deepcopy(self.input.witness)
        if len(witness) != 2 or len(witness[0]) > 520 or len(witness[1]) > 520:
            raise InvalidTransaction(f'Invalid witness for a {TX.P2WPKH} transaction')

        self.stack = list(witness)
        self.script = self.input.scriptcode()

        return self.verify_legacy() and len(self.stack) == 0

    def verify_p2wsh(self):
        if not version_byte(self.scriptPubKey) == 0x00:
            raise InvalidTransaction('Unknown witness version')

        witness = deepcopy(self.input.witness)
        self.stack = list(witness)
        witness_script = self.pop()

        if not len(witness_script) <= 10000:
            raise InvalidTransaction('Witness script too long')

        if not witness_program(self.scriptPubKey) == sha256(witness_script):
            raise InvalidTransaction('Redeem script hash does not match scriptPubKey')

        self.script = witness_script
        if any((len(item) > 520 for item in witness)):
            raise InvalidTransaction(f'Invalid witness for a {TX.P2WSH} transaction')

        return self.verify_legacy() and len(self.stack) == 0

    def OP_PUSH(self, n):
        """Push the next n bytes to the top of the stack"""
        self.push(self.read(n))

    def OP_DUP(self):
        """	Duplicates the top stack item."""
        top = self.pop()
        dupe = copy(top)
        self.push(top)
        self.push(dupe)

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
            raise OperationFailure('Top stack item is not True')

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

        sighash = self.tx.sighash(i=self.index, hashcode=hashcode)
        self.push(sig.verify_hash(sighash, pub))

    def OP_0(self):
        """An empty array of bytes is pushed onto the stack. (This is not a no-op: an item is added to the stack.)"""
        self.push(b'')

    def OP_CHECKMULTISIG(self):
        # Multisig m out of n
        # The stack at this point should look something like this
        # ['',
        #  '3045022100c38f1d0e340f4308b7f6e4bef0c8668e84793370924844a1076cc986f37047af02207cc29b61e85dc580ce85e01858e2e47eb3b8a80472ad784eb74538045e8172e801',
        #  '30450221009a6abea495730976b69f255282ee0c488e49769138b7048e749dd5215bdf8120022069f690fcaf5dba05f0537911b16b2868087440eb55a19dc6e89bcb83f1f35c6501',
        #  2,
        #  '02d271610ba72d9b0948ea0821fac77e0e6d10234a266b4828671a86a59073bb30',
        #  '0359446555d1c389782468191250c007a98393eb6e9db64649cd7ed1e7f9ca0cf3',
        #  '023779ee80b4a940503b1d630e7a3934503eecba5d571111f30841cdfbce0e8397',
        #  3]

        n = self.pop()
        keys = [PublicKey.decode(self.pop()) for _ in range(n)]

        m = self.pop()
        raw_signatures = [self.pop() for _ in range(m)]

        _ = self.pop()  # extra bytes in stack due to original implementation bug

        valid_signatures = []
        for raw_sig in raw_signatures:
            sig, hashcode = Signature.decode(raw_sig[:-1]), SIGHASH(raw_sig[-1])
            sighash = self.tx.sighash(self.index, hashcode=hashcode)
            for pub in keys:
                valid = sig.verify_hash(sighash, pub)
                if valid:
                    valid_signatures.append(valid)
                    break
            else:
                valid_signatures.append(False)

        self.push(sum(valid_signatures) >= m)

    def OP_CHECKMULTISIGVERIFY(self):
        self.op(OP.CHECHMULTISIG)
        self.op(OP.VERIFY)
