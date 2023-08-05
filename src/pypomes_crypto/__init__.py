from .crypto_pomes import (
    CRYPTO_HASH_ALGORITHM, crypto_hash,
)
from .crypto_pkcs7 import (
    Pkcs7Data,
)

__all__ = [
    # crypto_pomes
    "CRYPTO_HASH_ALGORITHM", "crypto_hash",
    # crypto_pkcs7
    "Pkcs7Data",
]

from importlib.metadata import version
__version__ = version("pypomes_crypto")
__version_info__ = tuple(int(i) for i in __version__.split(".") if i.isdigit())
