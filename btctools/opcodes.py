from enum import Enum, unique


@unique
class SIGHASH(Enum):
    ALL = 0x01
    NONE = 0x02
    SIGNLE = 0x03
    ANYONECANPAY = 0x80


@unique
class TX(Enum):
    P2PK = 'P2PK'
    P2PKH = 'P2PKH'
    P2SH = 'P2SH'
    P2WPKH = 'P2WPKH'
    P2WSH = 'P2WSH'
    UNKNOWN = None

    def __repr__(self):
        return '<%s.%s>' % (self.__class__.__name__, self.name)



@unique
class OP(Enum):

    _0 = 0x00
    PUSHDATA1 = 0x4c
    PUSHDATA2 = 0x4d
    PUSHDATA4 = 0x4e
    _1NEGATE = 0x4f
    _1 = 0x51
    _2 = 0x52
    _3 = 0x53
    _4 = 0x54
    _5 = 0x55
    _6 = 0x56
    _7 = 0x57
    _8 = 0x58
    _9 = 0x59
    _10 = 0x5a
    _11 = 0x5b
    _12 = 0x5c
    _13 = 0x5d
    _14 = 0x5e
    _15 = 0x5f
    _16 = 0x60
    NOP = 0x61
    VER = 0x62
    IF = 0x63
    NOTIF = 0x64
    VERIF = 0x65
    VERNOTIF = 0x66
    ELSE = 0x67
    ENDIF = 0x68
    VERIFY = 0x69
    RETURN = 0x6a
    TOTALSTACK = 0x6b
    FROMALTSTACK = 0x6c
    _2DROP = 0x6d
    _2DUP = 0x6e
    _3DUP = 0x6f
    _2OVER = 0x70
    _2ROT = 0x71
    _2SWAP = 0x72
    IFDUP = 0x73
    DEPTH = 0x74
    DROP = 0x75
    DUP = 0x76
    NIP = 0x77
    OVER = 0x78
    PICK = 0x79
    ROLL = 0x7a
    ROT = 0x7b
    SWAP = 0x7c
    TUCK = 0x7d
    CAT = 0x7e
    SUBSTR = 0x7f
    LEFT = 0x80
    RIGHT = 0x81
    SIZE = 0x82
    INVERT = 0x83
    AND = 0x84
    OR = 0x85
    XOR = 0x86
    EQUAL = 0x87
    EQUALVERIFY = 0x88
    RESERVED1 = 0x89
    RESERVED2 = 0x8a
    _1ADD = 0x8b
    _1SUB = 0x8c
    _2MUL = 0x8d
    _2DIV = 0x8e
    NEGATE = 0x8f
    ABS = 0x90
    NOT = 0x91
    _0NOTEQUAL = 0x92
    ADD = 0x93
    SUB = 0x94
    MUL = 0x95
    DIV = 0x96
    MOD = 0x97
    LSHIFT = 0x98
    RSHIFT = 0x99
    BOOLAND = 0x9a
    BOOLOR = 0x9b
    NUMEQUAL = 0x9c
    NUMEQUALVERIFY = 0x9d
    NUMNOTEQUAL = 0x9e
    LESSTHAN = 0x9f
    GREATERTHAN = 0xa0
    LESSTHANOREQUAL = 0xa1
    GREATERTHANOREQUAL = 0xa2
    MIN = 0xa3
    MAX = 0xa4
    WITHIN = 0xa5
    RIPEMD160 = 0xa6
    SHA1 = 0xa7
    SHA256 = 0xa8
    HASH160 = 0xa9
    HASH256 = 0xaa
    CODESEPERATOR = 0xab
    CHECKSIG = 0xac
    CHECKSIGVERIFY = 0xad
    CHECKMULTISIGVERIFY = 0xae
    NOP1 = 0xaf
    NOP2 = 0xb0
    CHECKLOCKTIMEVERIFY = 0xb1
    NOP3 = 0xb2
    NOP4 = 0xb3
    NOP5 = 0xb4
    NOP6 = 0xb5
    NOP7 = 0xb6
    NOP8 = 0xb7
    NOP9 = 0xb8
    NOP10 = 0xb9
    INVALIDOPCODE = 0xff


    PUSH1 = 0x01
    PUSH2 = 0x02
    PUSH3 = 0x03
    PUSH4 = 0x04
    PUSH5 = 0x05
    PUSH6 = 0x06
    PUSH7 = 0x07
    PUSH8 = 0x08
    PUSH9 = 0x09
    PUSH10 = 0x0a
    PUSH11 = 0x0b
    PUSH12 = 0x0c
    PUSH13 = 0x0d
    PUSH14 = 0x0e
    PUSH15 = 0x0f
    PUSH16 = 0x10
    PUSH17 = 0x11
    PUSH18 = 0x12
    PUSH19 = 0x13
    PUSH20 = 0x14
    PUSH21 = 0x15
    PUSH22 = 0x16
    PUSH23 = 0x17
    PUSH24 = 0x18
    PUSH25 = 0x19
    PUSH26 = 0x1a
    PUSH27 = 0x1b
    PUSH28 = 0x1c
    PUSH29 = 0x1d
    PUSH30 = 0x1e
    PUSH31 = 0x1f
    PUSH32 = 0x20
    PUSH33 = 0x21
    PUSH34 = 0x22
    PUSH35 = 0x23
    PUSH36 = 0x24
    PUSH37 = 0x25
    PUSH38 = 0x26
    PUSH39 = 0x27
    PUSH40 = 0x28
    PUSH41 = 0x29
    PUSH42 = 0x2a
    PUSH43 = 0x2b
    PUSH44 = 0x2c
    PUSH45 = 0x2d
    PUSH46 = 0x2e
    PUSH47 = 0x2f
    PUSH48 = 0x30
    PUSH49 = 0x31
    PUSH50 = 0x32
    PUSH51 = 0x33
    PUSH52 = 0x34
    PUSH53 = 0x35
    PUSH54 = 0x36
    PUSH55 = 0x37
    PUSH56 = 0x38
    PUSH57 = 0x39
    PUSH58 = 0x3a
    PUSH59 = 0x3b
    PUSH60 = 0x3c
    PUSH61 = 0x3d
    PUSH62 = 0x3e
    PUSH63 = 0x3f
    PUSH64 = 0x40
    PUSH65 = 0x41
    PUSH66 = 0x42
    PUSH67 = 0x43
    PUSH68 = 0x44
    PUSH69 = 0x45
    PUSH70 = 0x46
    PUSH71 = 0x47
    PUSH72 = 0x48
    PUSH73 = 0x49
    PUSH74 = 0x4a
    PUSH75 = 0x4b

    def __str__(self):
        s = super().__str__()
        return s.replace('.', '_').replace('__', '_')

    def __repr__(self):
        s = super().__repr__()
        return s.replace('.', '_').replace('__', '_')



