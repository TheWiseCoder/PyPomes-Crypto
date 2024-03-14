from .crypto_common import (
    CRYPTO_HASH_ALGORITHM, crypto_compute_hash,
)
from .crypto_pomes import (
    crypto_validate_p7s, crypto_validate_pdf,
)
from .crypto_pkcs7 import (
    CryptoPkcs7,
)

__all__ = [
    # crypto_common
    "CRYPTO_HASH_ALGORITHM", "crypto_compute_hash",
    # crypto_pomes
    "crypto_validate_p7s", "crypto_validate_pdf",
    # crypto_pkcs7
    "CryptoPkcs7",
]

from importlib.metadata import version
__version__ = version("pypomes_crypto")
__version_info__ = tuple(int(i) for i in __version__.split(".") if i.isdigit())
