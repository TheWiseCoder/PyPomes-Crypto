from __future__ import annotations
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa, x25519, x448
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


ChpHash = hashes.SHA224 | hashes.SHA256 | hashes.SHA384 | hashes.SHA512

ChpPublicKey = (dsa.DSAPublicKey | rsa.RSAPublicKey | ec.EllipticCurvePublicKey |
                ed25519.Ed25519PublicKey | ed448.Ed448PublicKey | x25519.X25519PublicKey | x448.X448PublicKey)

CRYPTO_DEFAULT_HASH_ALGORITHM: Final[HashAlgorithm] = \
    env_get_enum(key=f"{APP_PREFIX}_CRYPTO_DEFAULT_HASH_ALGORITHM",
                 enum_class=HashAlgorithm,
                 def_value=HashAlgorithm.SHA256)


def _chp_hash(alg: HashAlgorithm | str,
              errors: list[str] = None,
              logger: Logger = None) -> ChpHash:
    """
    Construct the *cryptography* package's hash object corresponding top *hash_alg*.

    The hash object is an instance of *cryptography.hazmat.primitives.hashes.<hash>*

    :param alg: the hash algorithm
    :param errors: incidental errors
    :return: the *Crypto* package's hash object, or *None* if error
    """
    result: ChpHash | None = None
    match alg:
        case HashAlgorithm.SHA224:
            result = hashes.SHA224()
        case HashAlgorithm.SHA256:
            result = hashes.SHA256()
        case HashAlgorithm.SHA384:
            result = hashes.SHA384()
        case HashAlgorithm.SHA512:
            result = hashes.SHA512()
        case _:
            msg = f"Hash algorithm not supported: '{alg}'"
            if logger:
                logger.error(msg=msg)
            if isinstance(errors, list):
                errors.append(msg)

    return result
