import sys
from Crypto.Cipher import AES
from Crypto.Cipher._mode_cbc import CbcMode
from Crypto.Cipher._mode_ccm import CcmMode
from Crypto.Cipher._mode_ecb import EcbMode
from Crypto.Cipher._mode_cfb import CfbMode
from Crypto.Cipher._mode_ctr import CtrMode
from Crypto.Cipher._mode_eax import EaxMode
from Crypto.Cipher._mode_ofb import OfbMode
from Crypto.Cipher._mode_openpgp import OpenPgpMode
from Crypto.Cipher._mode_siv import SivMode
from Crypto.Random import get_random_bytes
from enum import StrEnum
from pathlib import Path
from pypomes_core import (
    APP_PREFIX,
    file_get_data, exc_format, env_get_enum
)
from typing import Literal, Final

AesMode = type[CbcMode | CcmMode | CfbMode, CtrMode | EaxMode | EcbMode | OfbMode | OpenPgpMode | SivMode]


class SymmetricMode(StrEnum):
    """
    Chaining modes for AES.
    """
    CCM = "CCM"          # Counter with CBC-MAC
    EAX = "EAX"          # Authenticated Encryption with Associated Data
    GCM = "GCM"          # Galois/Counter
    OCB = "OCB"          # Offset CodeBook
    SIV = "SIV"          # Synthetic Initialization Vector


CRYPTO_DEFAULT_SYMMETRIC_MODE: Final[SymmetricMode] = \
    env_get_enum(key=f"{APP_PREFIX}_CRYPTO_DEFAULT_SYMMETRIC_MODE",
                 enum_class=SymmetricMode,
                 def_value=SymmetricMode.EAX)


def crypto_aes_encrypt(plaintext: Path | str | bytes,
                       key: bytes,
                       nonce: bytes = None,
                       header: bytes = None,
                       mode: SymmetricMode = SymmetricMode.EAX,
                       errors: list[str] = None) -> tuple[bytes, bytes, bytes]:
    """
    Symmetrically encrypt *plaintext* using the given *key*, and the chaining mode specified in *mode*.

    The *AES* (Advanced Encryption Standard) symmetric block cipher, as standardized by *NIST*
    (National Institute of Standards and Technology), is used. *AES* is the *de facto* standard
    for symmetric encryption.

    The nature of *plaintext* depends on its data type:
      - type *bytes*: *plaintext* holds the data (used as is)
      - type *str*: *plaintext* holds the data (used as utf8-encoded)
      - type *Path*: *plaintext* is a path to a file holding the data

    Besides providing guarantees over the *confidentiality* of the message, the cipher also provides guarantees over
    its *integrity* (i.e., it allows the receiver to establish whether the *ciphertext* was modified in transit).
    This is accomplished by combining *AEAD* (Authenticated Encryption with Associated Data) with one of
    the following supported chaining modes:
      - *CCM* (Counter with CBC-MAC)
      - *EAX* (Authenticated Encryption with Associated Data)
      - *GCM* (Galois/Counter)
      - *SIV* (Synthetic Initialization Vector)
      - *OCB* (Offset CodeBook)

    The mandatory *key* must be 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes long.
    For chaining mode *SIV* only, it doubles to 32, 48, or 64 bytes.

    A cryptographic *number once* value (*nonce*) may optionally be provided, but it should never be reused
    for any other encryption done with *key*. Requirements on its byte length depends upon the chaining mode used:
      - *CCM*: range [7 - 13] (11 recommended)
      - *EAX*: no restrictions (16 recommended)
      - *GCM*: no restrictions (16 recommended)
      - *SIV*: no restrictions (16 recommended)
      - *OCB*: range [1 - 15] (15 recommended)
    If *nonce* is not provided, the encryption is rendered deterministic for chaining mode *SIV*.
    For the other modes, a random byte string of the recommended length is automatically created.

    On successful encryption, a tuple with three byte strings is returned:
      - the encrypted message (*ciphertext*)
      - the *number once* value used (*nonce*)
      - the final authentication tag created (*MAC* tag)
    On decryption, the *ciphertext*, *key*, *header*, *nonce* and the *MAC* tag, as well as the chaining
    mode used, must be provided. The *MAC* tag allows the cipher to provide cryptographic *authentication*.

    :param plaintext: the message to encrypt
    :param key: the cryptographic key
    :param nonce: the optional cryptographic *number once* value
    :param header: the optional message header
    :param mode: the chaining mode to use (defaults to *EAX*)
    :param errors: incidental error messages (may be non-empty)
    :return: a tuple containing the encrypted message, and the *nonce* and *MAC* tag used, or *None* on error
    """
    # initialize the return variable
    result: tuple[bytes, bytes, bytes] | None = None

    # obtain the data for encryption
    plaindata: bytes = file_get_data(file_data=plaintext)

    # build the cypher
    # noinspection PyTypeChecker
    cipher: AesMode = AES.new(key=key,
                              mode=__to_symmetric_mode(mode))
    if header:
        cipher.update(header)
    cipher.nonce = nonce or get_random_bytes(16)

    # encrypt the data
    try:
        ciphertext, tag = cipher.encrypt_and_digest(plaintext=plaindata)
        result = (ciphertext, cipher.nonce, tag)
    except Exception as e:
        if isinstance(errors, list):
            exc_err: str = exc_format(exc=e,
                                      exc_info=sys.exc_info())
            errors.append(exc_err)

    return result


def crypto_aes_decrypt(ciphertext: Path | str | bytes,
                       key: bytes,
                       mac_tag: bytes,
                       nonce: bytes,
                       header: bytes = None,
                       mode: SymmetricMode = SymmetricMode.EAX,
                       errors: list[str] = None) -> bytes:
    """
    Symmetrically decrypt *ciphertext* using the given *key*, and the mode of operation specified in *mode*.

    It is assumed that the *AES* (Advanced Encryption Standard) symmetric block cipher, as standardized by *NIST*
    (National Institute of Standards and Technology), was used to generate *ciphertext*.
    *AES* is the *de facto* standard for symmetric encryption.

    The *key*, *header*, and *mode* must be the same ones used to generate *ciphertext*. The *number once*
    (*nonce*) and the authentication *MAC* tag (*mac_tag*) must be the ones returned by the encryption process.
    The *mac_tag* allows the cipher to provide cryptographic *authentication*.

    The nature of *ciphertext* depends on its data type:
      - type *bytes*: *ciphertext* holds the data (used as is)
      - type *str*: *ciphertext* holds the data (used as utf8-encoded)
      - type *Path*: *ciphertext* is a path to a file holding the data

    Besides providing guarantees over the *confidentiality* of the message, the cipher also provides guarantees over
    its *integrity* (i.e., it allows the receiver to establish whether the *ciphertext* was modified in transit).
    This is accomplished by combining *AEAD* (Authenticated Encryption with Associated Data) with one of
    the following supported chaining modes:
      - *CCM* (Counter with CBC-MAC)
      - *EAX* (Authenticated Encryption with Associated Data)
      - *GCM* (Galois/Counter)
      - *SIV* (Synthetic Initialization Vector)
      - *OCB* (Offset CodeBook)

    :param ciphertext: the message to decrypt
    :param key: the cryptographic key
    :param mac_tag: the *MAC* authentication tag
    :param nonce: the cryptographic *number once* value
    :param header: the optional message header
    :param mode: the chaining mode to use (defaults to *EAX*)
    :param errors: incidental error messages (may be non-empty)
    :return: the decrypted message, or *None* on error
    """
    # initialize the return variable
    result: bytes | None = None

    # obtain the data for decryption
    cipherdata: bytes = file_get_data(file_data=ciphertext)

    # build the cypher
    # noinspection PyTypeChecker
    cipher: AesMode = AES.new(key=key,
                              mode=__to_symmetric_mode(mode))
    if header:
        cipher.update(header)
    cipher.nonce = nonce

    # decrypt the data
    try:
        result = cipher.decrypt_and_verify(ciphertext=cipherdata,
                                           received_mac_tag=mac_tag)
    except Exception as e:
        if isinstance(errors, list):
            exc_error: str = exc_format(exc=e,
                                        exc_info=sys.exc_info())
            errors.append(exc_error)

    return result


def __to_symmetric_mode(tag: SymmetricMode) -> Literal[8, 9, 10, 11, 12]:
    """
    Convert the given SymmetricMode *tag* to its internal literal value.

    :param tag: the SymmetricMode value to convert
    :return: the corresponding internal literal value
    """
    result: Literal[8, 9, 10, 11, 12]
    match tag:
        case SymmetricMode.CCM:
            result = AES.MODE_CCM
        case SymmetricMode.SIV:
            result = AES.MODE_SIV
        case SymmetricMode.GCM:
            result = AES.MODE_GCM
        case SymmetricMode.OCB:
            result = AES.MODE_OCB
        case _:  # SymmetricMode.EAX:
            result = AES.MODE_EAX

    return result
