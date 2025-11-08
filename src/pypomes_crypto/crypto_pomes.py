import hashlib
import pickle
import sys
from asn1crypto.x509 import Certificate
from collections.abc import Iterable
from contextlib import suppress
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey.RSA import import_key, RsaKey
from Crypto.Signature import pkcs1_15
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from enum import StrEnum, auto
from io import BytesIO
from passlib.hash import argon2
from pathlib import Path
from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature
from pyhanko_certvalidator import ValidationContext
from pyhanko.keys import load_certs_from_pemder_data
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.status import PdfSignatureStatus
from pypomes_core import (
    APP_PREFIX,
    file_get_data, exc_format, env_get_enum
)
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


CRYPTO_DEFAULT_HASH_ALGORITHM: Final[HashAlgorithm] = \
    env_get_enum(key=f"{APP_PREFIX}_CRYPTO_DEFAULT_HASH_ALGORITHM",
                 enum_class=HashAlgorithm,
                 def_value=HashAlgorithm.SHA256)


def crypto_validate_p7s(p7s_file: Path | str | bytes,
                        p7s_payload: str | bytes = None,
                        errors: list[str] = None) -> bool:
    """
    Validate the digital signature of a PKCS#7 file.

     If a *list* is provided in *errors*, the following inconsistencies are reported:
        - The digital signature is invalid
        - Error from *CryptoPkcs7* instantiation

    :param p7s_file: a p7s file path, or the bytes thereof
    :param p7s_payload: a payload file path, or the bytes thereof
    :param errors: incidental error messages
    :return: *True* if the input data are consistent, *False* otherwise
    """
    # import
    from . import crypto_pkcs7

    # instantiate the return variable
    result: bool = False

    # instantiate the PKCS7 object
    pkcs7: crypto_pkcs7.CryptoPkcs7 | None = None
    try:
        pkcs7 = crypto_pkcs7.CryptoPkcs7(p7s_file=p7s_file,
                                         p7s_payload=p7s_payload)
    except Exception as e:
        if isinstance(errors, list):
            exc_error: str = exc_format(exc=e,
                                        exc_info=sys.exc_info())
            errors.append(exc_error)

    # was the PKCS7 object instanciated ?
    if pkcs7:
        # yes, verify the signature
        try:
            # noinspection PyUnboundLocalVariable
            rsa_key: RsaKey = import_key(extern_key=pkcs7.public_bytes)
            sig_scheme: PKCS115_SigScheme = pkcs1_15.new(rsa_key=rsa_key)
            sha256_hash: SHA256Hash = SHA256.new(data=pkcs7.payload)
            # TODO @gtnunes: fix the verification process  # noqa: FIX002, TD003
            sig_scheme.verify(msg_hash=sha256_hash,
                              signature=pkcs7.signature)
            result = True
        except ValueError:
            if isinstance(errors, list):
                errors.append("The digital signature is invalid")
        except Exception as e:
            if isinstance(errors, list):
                errors.append(exc_format(exc=e,
                                         exc_info=sys.exc_info()))
    return result


def crypto_validate_pdf(pdf_file: Path | str | bytes,
                        certs_file: Path | str | bytes = None,
                        errors: list[str] = None) -> bool:
    """
    Validate the digital signature of a PDF file.

    If a *list* is provided in *errors*, the following inconsistencies are reported:
        - The file is not digitally signed
        - The digital signature is not valid
        - The certificate used has been revoked
        - The certificate used is not trusted
        - The signature block is not intact
        - A bad seed value found

    :param pdf_file: a PDF file path, or the PDF file bytes
    :param certs_file: a path to a file containing a PEM/DER-encoded certificate chain, or the bytes thereof
    :param errors: incidental error messages
    :return: *True* if the input data are consistent, *False* otherwise
    """
    # initialize the return variable
    result: bool = True

    # obtain the PDF reader
    pdf_bytes: bytes = file_get_data(file_data=pdf_file)
    pdf_reader: PdfFileReader = PdfFileReader(stream=BytesIO(initial_bytes=pdf_bytes))

    # obtain the validation context
    certs: Iterable[Certificate] | None = None
    if certs_file:
        certs_bytes: bytes = file_get_data(file_data=certs_file)
        if certs_bytes:
            certs = load_certs_from_pemder_data(cert_data_bytes=certs_bytes)
    validation_context: ValidationContext = ValidationContext(trust_roots=certs)

    # obtain the list of digital signatures
    signatures: list[EmbeddedPdfSignature] = pdf_reader.embedded_signatures

    # were signatures retrieved ?
    if signatures:
        # yes, traverse the list verifying them
        for signature in signatures:
            error: str | None = None
            status: PdfSignatureStatus = validate_pdf_signature(embedded_sig=signature,
                                                                signer_validation_context=validation_context)
            if status.revoked:
                error = "The certificate used has been revoked"
            elif not status.intact:
                error = "The signature block is not intact"
            elif not status.trusted and certs:
                error = "The certificate used is not trusted"
            elif not status.seed_value_ok:
                error = "A bad seed value found"
            elif not status.valid:
                error = "The digital signature is not valid"

            # has an error been flagged ?
            if error:
                # yes, report it
                if isinstance(errors, list):
                    errors.append(error)
                result = False
    else:
        # no, report the problem
        if isinstance(errors, list):
            errors.append("The file is not digitally signed")
        result = False

    return result


def crypto_hash(msg: Path | str | bytes,
                alg: HashAlgorithm = CRYPTO_DEFAULT_HASH_ALGORITHM) -> bytes:
    """
    Compute the hash of *msg*, using the algorithm specified in *alg*.

    The nature of *msg* dependes on its data type:
        - type *bytes*: *msg* holds the data (used as is)
        - type *str*: *msg* holds the data (used as utf8-encoded)
        - type *Path*: *msg* is a path to a file holding the data
        - other: *pickle*'s serialization of *msg* is used

    Supported algorithms:
      *md5*, *blake2b*, *blake2s*, *sha1*, *sha224*, *sha256*, *sha384*,
      *sha512*, *sha3_224*, *sha3_256*, *sha3_384*, *sha3_512*, *shake_128*, *shake_256*.

    :param msg: the message to calculate the hash for
    :param alg: the algorithm to use (defaults to an environment-defined value, or to 'sha256')
    :return: the hash value obtained, or *None* if the hash could not be computed
    """
    # initialize the return variable
    result: bytes | None = None

    # instantiate the hasher (undeclared type type is '_Hash')
    hasher = hashlib.new(name=alg)

    # what is the type of the message ?
    if isinstance(msg, bytes):
        # argument is type 'bytes'
        hasher.update(msg)
        result = hasher.digest()

    elif isinstance(msg, str):
        # argument is type 'str'
        hasher.update(msg.encode())
        result = hasher.digest()

    elif isinstance(msg, Path):
        # argument is a file path
        buf_size: int = 128 * 1024
        with msg.open(mode="rb") as f:
            file_bytes: bytes = f.read(buf_size)
            while file_bytes:
                hasher.update(file_bytes)
                file_bytes = f.read(buf_size)
        result = hasher.digest()

    else:
        # argument is unknown
        with suppress(Exception):
            data: bytes = pickle.dumps(obj=msg)
            if data:
                hasher.update(data)
                result = hasher.digest()

    return result


def crypto_generate_rsa_keys(key_size: int = 2048) -> tuple[bytes, bytes]:
    """
    Generate and return a matching pair of *RSA* private and public keys.

    :param key_size: the key size (defaults to 2048 bytes)
    :return: a matching key pair *(private, public)* of serialized RSA keys
    """
    # generate the private key
    priv_key: RSAPrivateKey = rsa.generate_private_key(public_exponent=65537,
                                                       key_size=key_size)
    result_priv: bytes = priv_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.PKCS8,
                                                encryption_algorithm=serialization.NoEncryption())
    # generate the matching public key
    pub_key: RSAPublicKey = priv_key.public_key()
    result_pub: bytes = pub_key.public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)
    # return the key pair
    return result_priv, result_pub


def crypto_encrypt(plaintext: Path | str | bytes,
                   key: bytes,
                   errors: list[str] = None) -> bytes:
    """
    Symmetrically encrypt *plaintext* using the given *key*.

    The *ECB* (Electronic CodeBook) symmetric block cipher is used. This is the most basic but also
    the weakest mode of operation available. Its use should be restricted to non-critical messages,
    or otherwise should be combined with a stronger cipher.

    It should also be noted that this cipher does not provides guarantees over the *integrity* of the message
    (i.e., it does not allow the receiver to establish whether the *ciphertext* was modified in transit).
    For a top-of-the-line symmetric block cipher, providing quality message *confidentiality* and *integrity*,
    consider using *crypto_aes_encrypt()/crypto_aes_decrypt()* in this package.

    The nature of *plaintext* depends on its data type:
      - type *bytes*: *plaintext* holds the data (used as is)
      - type *str*: *plaintext* holds the data (used as utf8-encoded)
      - type *Path*: *plaintext* is a path to a file holding the data

    The mandatory *key* must be 16, 24, or 32 bytes long.

    :param plaintext: the message to encrypt
    :param key: the cryptographic key (byte length must be 16, 24 or 32)
    :param errors: incidental error messages
    :return: the encrypted message, or *None* if error
    """
    # initialize the return variable
    result: bytes | None = None

    # obtain the data for encryption
    plaindata: bytes = file_get_data(file_data=plaintext)

    # build the cipher
    cipher: AES = AES.new(key=key,
                          mode=AES.MODE_ECB)
    # encrypt the data
    try:
        result = cipher.encrypt(plaintext=pad(data_to_pad=plaindata,
                                              block_size=AES.block_size))
    except Exception as e:
        if isinstance(errors, list):
            exc_error: str = exc_format(exc=e,
                                        exc_info=sys.exc_info())
            errors.append(exc_error)

    return result


def crypto_decrypt(ciphertext: Path | str | bytes,
                   key: bytes,
                   errors: list[str] = None) -> bytes:
    """
    Symmetrically decrypt *ciphertext* using the given *key*.

    It is assumed that the *ECB* (Electronic CodeBook) symmetric block cipher was used to generate *ciphertext*.
    This is the most basic but also the weakest mode of operation available. Its use should be restricted to
    non-critical messages, or otherwise should be combined with a stronger cipher.

    It should also be noted that this cipher does not provides guarantees over the *integrity* of the message
    (i.e., it does not allow the receiver to establish whether *ciphertext* was modified in transit).
    For a top-of-the-line symmetric block cipher, providing quality message *confidentiality* and *integrity*,
    consider using *crypto_aes_encrypt()/crypto_aes_decrypt()* in this package.

    The nature of *ciphertext* depends on its data type:
      - type *bytes*: *ciphertext* holds the data (used as is)
      - type *str*: *ciphertext* holds the data (used as utf8-encoded)
      - type *Path*: *ciphertext* is a path to a file holding the data

     The *key* must be the same one used to generate *ciphertext*.

    :param ciphertext: the message to decrypt
    :param key: the cryptographic key
    :param errors: incidental error messages
    :return: the decrypted message, or *None* if error
    """
    # initialize the return variable
    result: bytes | None = None

    # obtain the data for decryption
    cipherdata: bytes = file_get_data(file_data=ciphertext)

    # build the cipher
    cipher: AES = AES.new(key=key,
                          mode=AES.MODE_ECB)
    # decrypt the data
    try:
        # HAZARD: the misnamed parameter ('plaintext') is left unnamed
        plaindata: bytes = cipher.decrypt(cipherdata)
        result = unpad(padded_data=plaindata,
                       block_size=AES.block_size)
    except Exception as e:
        if isinstance(errors, list):
            exc_error: str = exc_format(exc=e,
                                        exc_info=sys.exc_info())
            errors.append(exc_error)

    return result


def crypto_pwd_encrypt(pwd: str,
                       salt: bytes,
                       errors: list[str] = None) -> str:
    """
    Encrypt a password given in *pwd*, using the provided *salt*, and return it.

    :param pwd: the password to encrypt
    :param salt: the salt value to use (must be at least 8 bytes long)
    :param errors: incidental error messages
    :return: the encrypted password, or *None* if error
    """
    # initialize the return variable
    result: str | None = None

    try:
        pwd_hash: str = argon2.using(salt=salt).hash(secret=pwd)
        result = pwd_hash[pwd_hash.rfind("$")+1:]
    except Exception as e:
        if isinstance(errors, list):
            exc_error: str = exc_format(exc=e,
                                        exc_info=sys.exc_info())
            errors.append(exc_error)

    return result


def crypto_pwd_verify(plain_pwd: str,
                      cipher_pwd: str,
                      salt: bytes,
                      errors: list[str] = None) -> bool:
    """
    Verify, using the provided *salt*, whether the plaintext and encrypted passwords match.

    :param plain_pwd: the plaintext password
    :param cipher_pwd: the encryped password to verify
    :param salt: the salt value to use (must be at least 8 bytes long)
    :param errors: incidental error messages
    :return: *True* if they match, *False* otherwise
    """
    pwd_hash: str = crypto_pwd_encrypt(pwd=plain_pwd,
                                       salt=salt,
                                       errors=errors)
    return isinstance(pwd_hash, str) and cipher_pwd == pwd_hash
