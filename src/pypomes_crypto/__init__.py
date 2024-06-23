from .crypto_pkcs7 import (
    CryptoPkcs7,
)
from .crypto_pomes import (
    CRYPTO_DEFAULT_HASH_ALGORITHM,
    crypto_validate_p7s, crypto_validate_pdf, crypto_compute_hash,
)

__all__ = [
    # crypto_pkcs7
    "CryptoPkcs7",
    # crypto_pomes
    "CRYPTO_DEFAULT_HASH_ALGORITHM",
    "crypto_validate_p7s", "crypto_validate_pdf", "crypto_compute_hash",
]

from importlib.metadata import version
__version__ = version("pypomes_crypto")
__version_info__ = tuple(int(i) for i in __version__.split(".") if i.isdigit())
