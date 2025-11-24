import hashlib
import pickle
import sys
from asn1crypto import cms
from collections.abc import Iterable
from contextlib import suppress
from Crypto.Cipher import AES
from Crypto.Cipher._mode_ecb import EcbMode
from Crypto.Util.Padding import pad, unpad
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from io import BytesIO
from logging import Logger
from passlib.hash import argon2
from pathlib import Path
from pyhanko.keys import load_certs_from_pemder_data
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature
from pyhanko.sign.validation.status import PdfSignatureStatus
from pyhanko_certvalidator import ValidationContext
from pypomes_core import file_get_data, exc_format

from .crypto_common import (
    CRYPTO_DEFAULT_HASH_ALGORITHM,
    HashAlgorithm, ChpHash, _chp_hash
)


def crypto_hash(msg: Path | str | bytes,
                alg: HashAlgorithm | str = CRYPTO_DEFAULT_HASH_ALGORITHM) -> bytes:
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

    if alg in HashAlgorithm:
        # instantiate the hasher (undeclared type is '_Hash')
        hasher = hashlib.new(name=alg)

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
    :param errors: incidental error messages (may be non-empty)
    :return: the encrypted message, or *None* if error
    """
    # initialize the return variable
    result: bytes | None = None

    # obtain the data for encryption
    plaindata: bytes = file_get_data(file_data=plaintext)

    # build the cipher
    cipher: EcbMode = AES.new(key=key,
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
    :param errors: incidental error messages (may be non-empty)
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
    :param errors: incidental error messages (may be non-empty)
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
    :param errors: incidental error messages (may be non-empty)
    :return: *True* if they match, *False* otherwise
    """
    pwd_hash: str = crypto_pwd_encrypt(pwd=plain_pwd,
                                       salt=salt,
                                       errors=errors)
    return isinstance(pwd_hash, str) and cipher_pwd == pwd_hash


def crypto_verify_p7s(p7s_data: Path | str | bytes,
                      doc_data: Path | str | bytes = None,
                      errors: list[str] = None,
                      logger: Logger = None) -> bool | None:
    """
    Verify a PKCS#7 signature against a document.

    The natures of *p7s_data* and *doc_data* depend on their respective data types:
      - type *bytes*: holds the data (used as is)
      - type *str*: holds the data (used as utf8-encoded)
      - type *Path*: is a path to a file holding the data

    Both attached and detached signatures are properly handled, and full cryptographic verification
    (digest + RSA signature check) is performed. The PKCS#7 data provided in *p7s_data* contains the
    A1 certificate and its corresponding public key, the certificate chain, the original payload
    (if *attached* mode, only), and the digital signature.

    :param p7s_data: the PKCS#7 signature data containing A1 certificate
    :param doc_data: the original document data (required for detached mode)
    :param errors: incidental errors (may be non-empty)
    :param logger: optional logger
     :return: *True* if signature is valid, *False* otherwise, or *None* if error
    """
    # initialize the return variable
    result: bool | None = None

    # retrieve the certificate raw bytes
    p7_bytes: bytes = file_get_data(file_data=p7s_data)

    # parse the CMS structure
    err_msg: str | None = None
    signed_data: cms.SignedData | None = None
    payload: bytes | None = None
    content_info: cms.ContentInfo = cms.ContentInfo.load(encoded_data=p7_bytes)
    if content_info["content_type"].native == "signed_data":
        # signatures in PKCS#7 are parallel, not chained, so they share the same payload
        signed_data = content_info["content"]
        embedded_content: bytes = signed_data["encap_content_info"]["content"].native

        # determine attached vs detached
        if embedded_content:
            # attached mode: use embedded content for digest
            payload = embedded_content
        elif doc_data:
            # detached mode: use external document
            payload = file_get_data(file_data=doc_data)
        else:
            err_msg = "For detached mode, a payload file must be provided"
    else:
        err_msg = "'p7_data' is not a signed PKCS#7 file"

    if not err_msg:
        # extract the signatures
        signer_infos: list[cms.SignerInfo] = signed_data["signer_infos"]

        if signer_infos:
            # traverse the signatures
            result = True
            for signer_info in signer_infos:
                # structure and compute the digest
                signature_bytes: bytes = signer_info["signature"].native
                signature_algorithm: str = signer_info["signature_algorithm"]["algorithm"].native
                alg_name: str = signer_info["digest_algorithm"]["algorithm"].native
                chp_hash: ChpHash = _chp_hash(alg=HashAlgorithm(alg_name))
                computed_digest: bytes = crypto_hash(msg=payload,
                                                     alg=HashAlgorithm(alg_name))
                # extract the certificate
                cert_data = signed_data["certificates"][0].chosen.dump()
                cert = x509.load_der_x509_certificate(data=cert_data)
                public_key = cert.public_key()
                try:
                    if isinstance(public_key, RSAPublicKey):
                        # determine the signature padding used
                        if "pss" in signature_algorithm:
                            signature_padding: padding.AsymmetricPadding = padding.PSS(
                                mgf=padding.MGF1(algorithm=chp_hash),
                                salt_length=padding.PSS.MAX_LENGTH
                            )
                        else:
                            signature_padding: padding.AsymmetricPadding = padding.PKCS1v15()
                        public_key.verify(signature=signature_bytes,
                                          data=computed_digest,
                                          padding=signature_padding,
                                          algorithm=Prehashed(chp_hash))
                    else:
                        public_key.verify(signature=signature_bytes,
                                          data=computed_digest,
                                          algorithm=Prehashed(chp_hash))
                    if logger:
                        logger.debug(msg="Signature verification successful")
                except Exception as e:
                    if logger:
                        logger.warning(msg=f"Signature verification failed: {e}")
                    result = False
                    break
        else:
            # signatures not retrieved, report the problem
            err_msg = "The file is not digitally signed"

    if err_msg:
        if logger:
            logger.error(msg=err_msg)
        if isinstance(errors, list):
            errors.append(err_msg)

    if result and logger:
        logger.debug(msg="Signature verification successful")

    return result


def crypto_verify_pdf(pdf_data: Path | str | bytes,
                      cert_chain: Path | str | bytes = None,
                      errors: list[str] = None,
                      logger: Logger = None) -> bool | None:
    """
    Validate the embedded digital signatures of a PDF file in *PAdES* format.

    The nature of *pdf_data* depends on its data type:
      - type *bytes*: *pdf_data* holds the data (used as is)
      - type *str*: *pdf_data* holds the data (used as utf8-encoded)
      - type *Path*: *pdf_data* is a path to a file holding the data

    The folowing inconsistencies are verified, for each signature:
        - The digital signature is not valid
        - The certificate used has been revoked
        - The certificate used is not trusted
        - The signature block is not intact
        - A bad seed value was found

    The operation terminates on the first verification failure, regardless of the number of existing signatures.
    If *pdf_data* is not digitally signed, this is taken as an error.

    :param pdf_data: a PDF file path, or the PDF file bytes
    :param cert_chain: optional PEM/DER-encoded certificate chain
    :param errors: incidental error messages (may be non-empty)
    :param logger: optional logger
    :return: *True* if the signature is valid, *False* otherwise, or *None* if error
    """
    # initialize the return variable
    result: bool | None = None

    # obtain the PDF reader
    pdf_bytes: bytes = file_get_data(file_data=pdf_data)
    pdf_reader: PdfFileReader = PdfFileReader(stream=BytesIO(initial_bytes=pdf_bytes),
                                              strict=False)
    # obtain the validation context
    certs: Iterable[x509.Certificate] | None = None
    if cert_chain:
        certs_bytes: bytes = file_get_data(file_data=cert_chain)
        if certs_bytes:
            certs = load_certs_from_pemder_data(cert_data_bytes=certs_bytes)
    validation_context: ValidationContext = ValidationContext(trust_roots=certs)

    # obtain the list of digital signatures
    signatures: list[EmbeddedPdfSignature] = pdf_reader.embedded_signatures

    if signatures:
        # traverse the signatures
        result = True
        for signature in signatures:
            msg: str | None = None
            status: PdfSignatureStatus = validate_pdf_signature(embedded_sig=signature,
                                                                signer_validation_context=validation_context)
            if status.revoked:
                msg = "The certificate used has been revoked"
            elif not status.intact:
                msg = "The signature block is not intact"
            elif not status.trusted and certs:
                msg = "The certificate used is not trusted"
            elif not status.seed_value_ok:
                msg = "A bad seed value found"
            elif not status.valid:
                msg = "The digital signature is not valid"

            if msg:
                # an error has been flagged, report it
                if logger:
                    logger.warning(msg=msg)
                result = False
                break
    else:
        # signatures not retrieved, report the problem
        msg: str = "The file is not digitally signed"
        if logger:
            logger.error(msg=msg)
        if isinstance(errors, list):
            errors.append(msg)

    if result and logger:
        logger.debug(msg="Signature verification successful")

    return result
