import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from enum import StrEnum
from pathlib import Path
from pypomes_core import (
    APP_PREFIX,
    file_get_data, exc_format, env_get_str
)
from typing import Literal, Final


class SymmetricMode(StrEnum):
    CCM = "CCM"          # Counter with CBC-MAC
    EAX = "EAX"          # Authenticated Encryption with Associated Data
    GCM = "GCM"          # Galois/Counter
    OCB = "OCB"          # Offset CodeBook
    SIV = "SIV"          # Synthetic Initialization Vector


_cipher: str = env_get_str(key=f"{APP_PREFIX}_CRYPTO_DEFAULT_SYMMETRIC_MODE",
                           values=list(map(str, SymmetricMode)),
                           def_value="EAX")
CRYPTO_DEFAULT_SYMMETRIC_MODE: Final[SymmetricMode] = SymmetricMode(_cipher)


def crypto_aes_encrypt(errors: list[str] | None,
                       plaintext: Path | str | bytes,
                       key: bytes,
                       header: bytes = None,
                       nonce: bytes = None,
                       mode: SymmetricMode = SymmetricMode.EAX) -> (bytes, bytes, bytes):
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

    :param errors: incidental error messages
    :param plaintext: the message to encrypt
    :param key: the cryptographic key
    :param header: the optional message header
    :param nonce: the optional cryptographic *number once* value
    :param mode: the chaining mode to use (defaults to *EAX*)
    :return: a tuple containing the encrypted message, and the *nonce* and *MAC* tag used, or *None* on error
    """
    # initialize the return variable
    result: tuple[bytes, bytes, bytes] | None = None

    # obtain the data for encryption
    plaindata: bytes = file_get_data(file_data=plaintext)

    # build the cypher
    cipher: AES = AES.new(key=key,
                          mode=__to_symmetric_mode(mode),
                          nonce=nonce)
    if header:
        cipher.update(header)

    # encrypt the data
    try:
        result_nonce: bytes = nonce or cipher.nonce
        result_ciphertext, result_tag = cipher.encrypt_and_digest(plaintext=plaindata)
        result = (result_ciphertext, result_nonce, result_tag)
    except Exception as e:
        if isinstance(errors, list):
            exc_error: str = exc_format(exc=e,
                                        exc_info=sys.exc_info())
            errors.append(exc_error)

    return result


def crypto_aes_decrypt(errors: list[str] | None,
                       ciphertext: Path | str | bytes,
                       key: bytes,
                       nonce: bytes,
                       mac_tag: bytes,
                       header: bytes = None,
                       mode: SymmetricMode = SymmetricMode.EAX) -> bytes:
    """
    Symmetrically decrypt *ciphertext* using the given *key*, and the mode of operation specified in *mode*.

    It is assumed that the *AES* (Advanced Encryption Standard) symmetric block cipher, as standardized by *NIST*
    (National Institute of Standards and Technology), was used to generate *ciphertext*.
    *AES* is the *de facto* standard for symmetric encryption.

    The *key*, *header*, and *mode* must be the same ones used to generate *ciphertext*. The *number once*
    (*nonce*) and the authentication *MAC* tag (*mac_tag*) must be the ones returned by the encryption process.
    The *mac_tag* allows the cipher to provide cryptographic *authentication*.

    The nature of *ciphertext* dependes on its data type:
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

    :param errors: incidental error messages
    :param ciphertext: the message to decrypt
    :param key: the cryptographic key
    :param nonce: the cryptographic *number once* value
    :param mac_tag: the *MAC* authentication tag
    :param header: the optional message header
    :param mode: the chaining mode to use (defaults to *EAX*)
    :return: the decrypted message, or *None* on error
    """
    # initialize the return variable
    result: bytes | None = None

    # obtain the data for decryption
    cipherdata: bytes = file_get_data(file_data=ciphertext)

    # build the cypher
    cipher: AES = AES.new(key=key,
                          mode=__to_symmetric_mode(mode),
                          nonce=nonce)
    if header:
        cipher.update(header)

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


def crypto_aes_get_nonce() -> bytes:
    """
    Generate and return a random *number once* (*nonce*) value for cryptography use.

    This function is provided as a convenience, as it simply
    invokes *Crypto.Random.get_random_bytes(16)* for a suitable value.

    :return: a random *number once* value
    """
    return get_random_bytes(16)


def __to_symmetric_mode(tag: SymmetricMode) -> Literal:
    """
    Convert the given SymmetricMode *tag* to its internal literal value.

    :param tag: the SymmetricMode value to convert
    :return: the corresponding internal literal value
    """
    result: Literal = None
    match tag.value:
        case "CCM":
            result = AES.MODE_CCM
        case "EAX":
            result = AES.MODE_EAX
        case "GCM":
            result = AES.MODE_GCM
        case "SIV":
            result = AES.MODE_SIV
        case "OCB":
            result = AES.MODE_OCB

    return result
