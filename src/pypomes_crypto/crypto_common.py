from __future__ import annotations
from cryptography.hazmat.primitives import hashes
from enum import StrEnum, auto
from logging import Logger
from pypomes_core import env_get_enum, APP_PREFIX
from typing import Final


class SignatureMode(StrEnum):
    """
    Location of signatures with respect to the signed files.
    """
    ATTACHED = auto()
    DETACHED = auto()


class SignatureType(StrEnum):
    """
    Types of cryptographic signatures in documents.
    """
    CADES = "CAdES"
    PADES = "PAdES"
    XADES = "XAdES"


class HashAlgorithm(StrEnum):
    """
    Supported hash algorithms.
    """
    MD5 = auto()
    BLAKE2B = auto()
    BLAKE2S = auto()
    SHA1 = auto()
    SHA224 = auto()
    SHA256 = auto()
    SHA384 = auto()
    SHA512 = auto()
    SHA3_224 = auto()
    SHA3_256 = auto()
    SHA3_384 = auto()
    SHA3_512 = auto()
    SHAKE_128 = auto()
    SHAKE_256 = auto()


CryptographyHashes = hashes.SHA224 | hashes.SHA256 | hashes.SHA384 | hashes.SHA512

CRYPTO_DEFAULT_HASH_ALGORITHM: Final[HashAlgorithm] = \
    env_get_enum(key=f"{APP_PREFIX}_CRYPTO_DEFAULT_HASH_ALGORITHM",
                 enum_class=HashAlgorithm,
                 def_value=HashAlgorithm.SHA256)


def _cryptography_hash(hash_alg: HashAlgorithm | str,
                       errors: list[str] = None,
                       logger: Logger = None) -> CryptographyHashes:
    """
    Construct the *Crypto* package's hash object corresponding top *hash_alg*.

    :param hash_alg: the hash algorithm
    :param errors: incidental errors
    :return: the *Crypto* package's hash object, or *None* if error
    """
    result: CryptographyHashes | None = None
    match hash_alg:
        case HashAlgorithm.SHA224:
            from cryptography.hazmat.primitives.hashes import SHA224
            result = SHA224()
        case HashAlgorithm.SHA256:
            from cryptography.hazmat.primitives.hashes import SHA256
            result = SHA256()
        case HashAlgorithm.SHA384:
            from cryptography.hazmat.primitives.hashes import SHA384
            result = SHA384()
        case HashAlgorithm.SHA512:
            from cryptography.hazmat.primitives.hashes import SHA512
            result = SHA512()
        case _:
            msg = f"Hash algorithm not supported: '{hash_alg}'"
            if logger:
                logger.error(msg=msg)
            if isinstance(errors, list):
                errors.append(msg)

    return result
