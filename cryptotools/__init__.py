"""
Zero dependency implementation of common cryptographic functions for working with cryptocurrency.
"""

import pkgutil

from .BTC import *
from .BTC.HD import *
from .ECDSA import *
from .RSA import *
from .transformations import *
from .number_theory_stuff import *
from .message import *

__all__ = []

for loader, module_name, is_pkg in  pkgutil.walk_packages(__path__):
    _module = loader.find_module(module_name).load_module(module_name)
    module_exports = getattr(_module, '__all__', [])
    __all__.extend(module_exports)

__version__ = "0.1"