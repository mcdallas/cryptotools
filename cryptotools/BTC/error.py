from urllib.error import HTTPError


class TransactionError(Exception):
    def __init__(self, message, tx=None, data=None, txhash=None):
        self.message = message
        self.tx = tx
        self.data = data
        self.txhash = txhash


class SerializationError(TransactionError):
    pass


class ValidationError(TransactionError):
    pass


class SigningError(TransactionError):
    pass


class UpstreamError(Exception):
    pass


class ScriptValidationError(Exception):
    pass


class Base58DecodeError(Exception):
    pass


class Bech32DecodeError(Exception):
    pass


class InvalidAddress(Exception):
    pass

class BackendError(Exception):
    pass

class NotSupportedError(BackendError):
    pass