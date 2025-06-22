"""
:mod:`pkcs11` defines a high-level, "Pythonic" interface to PKCS#11.
"""

from .constants import *  # noqa: F403
from .exceptions import *  # noqa: F403
from .mechanisms import *  # noqa: F403
from .types import *  # noqa: F403
from .util import dh, dsa, ec, rsa, x509  # noqa: F401

_loaded = {}


def lib(so):
    """
    Wrap the main library call coming from Cython with a preemptive
    dynamic loading.
    """
    global _loaded

    try:
        _lib = _loaded[so]
        if not _lib.initialized:
            _lib.initialize()
        return _lib
    except KeyError:
        pass

    from . import _pkcs11

    _lib = _pkcs11.lib(so)
    _loaded[so] = _lib

    return _lib
