import hashlib
import pickle
import sys
from asn1crypto import cms, pem
from contextlib import suppress
from Crypto.Cipher import AES
from Crypto.Cipher._mode_ecb import EcbMode
from Crypto.Util.Padding import pad, unpad
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from io import BytesIO
from logging import Logger
from passlib.hash import argon2
from pathlib import Path
from PyPDF2 import PdfReader
from PyPDF2.generic import ArrayObject, ByteStringObject, DictionaryObject, Field
from pypomes_core import file_get_data, exc_format

from .crypto_common import (
    CRYPTO_DEFAULT_HASH_ALGORITHM, HashAlgorithm,
    _cms_build_cert_chain, _cms_verify_payload_hash,
    _cms_get_content_info, _cms_get_payload,
    _crypto_get_signature_padding, _crypto_verify_signature
)


def crypto_hash(msg: BytesIO | Path | str | bytes,
                alg: HashAlgorithm | str = CRYPTO_DEFAULT_HASH_ALGORITHM) -> bytes:
    """
    Compute the hash of *msg*, using the algorithm specified in *alg*.

    The nature of *msg* dependes on its data type:
        - type *BytesIO*: *sg* is a byte stream
        - type *Path*: *msg* is a path to a file holding the data
        - type *bytes*: *msg* holds the data (used as is)
        - type *str*: *msg* holds the data (used as utf8-encoded)
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

        elif isinstance(msg, BytesIO):
            # argument is type 'stream'
            msg.seek(0)
            msg_bytes: bytes = msg.read()
            hasher.update(msg_bytes)
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


def crypto_encrypt(plaintext: BytesIO | Path | str | bytes,
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
      - type *BytesIO*: *plaintext* is a byte stream
      - type *Path*: *plaintext* is a path to a file holding the data
      - type *bytes*: *plaintext* holds the data (used as is)
      - type *str*: *plaintext* holds the data (used as utf8-encoded)

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


def crypto_decrypt(ciphertext: BytesIO | Path | str | bytes,
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
        - type *BytesIO*: *ciphertext* is a byte stream
        - type *Path*: *ciphertext* is a path to a file holding the data
        - type *bytes*: *ciphertext* holds the data (used as is)
        - type *str*: *ciphertext* holds the data (used as utf8-encoded)

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


def crypto_verify_p7x(p7x_in: BytesIO | Path | str | bytes,
                      doc_in: BytesIO | Path | str | bytes = None,
                      errors: list[str] = None,
                      logger: Logger = None) -> bool | None:
    """
    Verify a PKCS#7 signature against a document.

    The natures of *p7x_in* and *doc_in* depend on their respective data types:
      - type *BytesIO*: is a byte stream
      - type *Path*: is a path to a file holding the data
      - type *bytes*: holds the data (used as is)
      - type *str*: holds the data (used as utf8-encoded)

    Both attached and detached signatures are properly handled, and full cryptographic verification
    (digest + RSA signature check) is performed. The PKCS#7 data provided in *p7s_data* contains the
    A1 certificate and its corresponding public key, the certificate chain, the original payload
    (if *attached* mode, only), and the digital signature.

    :param p7x_in: the PKCS#7 signature data containing A1 certificate, in *DER* or *PEM* format
    :param doc_in: the original document data (required for detached mode)
    :param errors: incidental errors (may be non-empty)
    :param logger: optional logger
     :return: *True* if all signatures are valid, *False* otherwise, or *None* if error
    """
    # initialize the return variable
    result: bool | None = True

    # define a local errors list
    curr_errors: list[str] = []

    # retrieve the certificate raw bytes (if PEM, convert to DER)
    p7s_bytes: bytes = file_get_data(file_data=p7x_in)
    if pem.detect(p7s_bytes):
        _, _, p7s_bytes = pem.unarmor(pem_bytes=p7s_bytes)

    # retrieve the CMS base structure and the authenticated data
    content_info: cms.ContentInfo = _cms_get_content_info(p7s_bytes=p7s_bytes,
                                                          errors=curr_errors,
                                                          logger=logger)
    signed_data: cms.SignedData = content_info["content"] if content_info else None

    # signatures in PKCS#7 share the same payload
    payload: bytes = _cms_get_payload(signed_data=signed_data,
                                      payload_bytes=file_get_data(file_data=doc_in),
                                      errors=curr_errors,
                                      logger=logger) if signed_data else None

    if content_info and signed_data and payload:
        # extract the signatures
        signer_infos: cms.SignerInfos = signed_data["signer_infos"]

        # traverse the signatures
        for signer_info in (signer_infos or []):
            # retrieve the signature properties
            hash_algorithm: HashAlgorithm = HashAlgorithm(signer_info["digest_algorithm"]["algorithm"].native)
            signature: bytes = signer_info["signature"].native
            signature_algorithm: str = signer_info["signature_algorithm"]["algorithm"].native

            # extract the certificate chain and the signer's certificate proper
            cert_data: tuple[list[bytes], int] = _cms_build_cert_chain(signed_data=signed_data,
                                                                       signer_info=signer_info)
            cert_chain: list[bytes] = cert_data[0]
            cert_ord: int = cert_data[1]
            signer_cert: x509.Certificate = x509.load_der_x509_certificate(data=cert_chain[cert_ord])
            public_key: PublicKeyTypes = signer_cert.public_key()
            signed_attrs: cms.CMSAttributes = signer_info["signed_attrs"]
            signature_padding: padding.AsymmetricPadding = \
                _crypto_get_signature_padding(public_key=public_key,
                                              signature_alg=signature_algorithm,
                                              hash_alg=hash_algorithm)
            # identify signer
            subject: x509.name.Name = signer_cert.subject
            signer_cn: str = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

            # extract and validate the payload hash
            computed_hash: bytes = _cms_verify_payload_hash(signed_attrs=signed_attrs,
                                                            payload=payload,
                                                            hash_alg=hash_algorithm,
                                                            errors=curr_errors,
                                                            logger=logger)
            if curr_errors:
                break

            # verify the signature
            # ('errors' is not passed, as an invalid signature is not an error in the current context)
            if not _crypto_verify_signature(public_key=public_key,
                                            signature=signature,
                                            signature_padding=signature_padding,
                                            signer_cn=signer_cn,
                                            signed_attrs=signed_attrs,
                                            payload_hash=computed_hash,
                                            hash_algorithm=hash_algorithm,
                                            errors=None,
                                            logger=logger):
                result = False

    if curr_errors:
        result = None
        if isinstance(errors, list):
            errors.extend(curr_errors)

    return result


def crypto_verify_pdf(doc_in: BytesIO | Path | str | bytes,
                      doc_pwd: str = None,
                      errors: list[str] = None,
                      logger: Logger = None) -> bool | None:
    """
    Validate the embedded digital signatures of a PDF file in *PAdES* format.

    The nature of *doc_in* depends on its data type:
      - type *BytesIO*: *doc_in* is a byte stream
      - type *Path*: *doc_in* is a path to a file holding the data
      - type *bytes*: *doc_in* holds the data (used as is)
      - type *str*: *doc_in* holds the data (used as utf8-encoded)

    If *doc_in* is encrypted, the decryption password must be provided in *doc_pwd*.

    :param doc_in: a digitally signed, *PAdES* conformant, PDF file
    :param doc_pwd: optional password for file decryption
    :param errors: incidental errors (may be non-empty)
    :param logger: optional logger
    :return: *True* if all signatures are valid, *False* otherwise, or *None* if error
    """
    # initialize the return variable
    result: bool | None = True

    # retrieve the PDF data
    pdf_bytes: bytes = file_get_data(file_data=doc_in)

    # define a local errors list
    curr_errors: list[str] = []

    pdf_stream: BytesIO = BytesIO(initial_bytes=pdf_bytes)
    pdf_stream.seek(0)

    # retrieve the signature fields
    reader: PdfReader = PdfReader(stream=pdf_stream,
                                  password=doc_pwd)
    sig_fields: list[Field] = [field for field in reader.get_fields().values()
                               if field.get("/FT") == "/Sig"] or []

    # process the signature fields
    for sig_field in sig_fields:
        sig_dict: DictionaryObject = sig_field.get("/V")
        contents: ByteStringObject = sig_dict.get("/Contents")

        # extract the payload
        byte_range: ArrayObject = sig_dict.get("/ByteRange")
        from_1, len_1, from_2, len_2 = byte_range
        payload: bytes = pdf_bytes[from_1:from_1+len_1] + pdf_bytes[from_2:from_2+len_2]

        # extract signature data (CMS structure)
        sig_obj: ByteStringObject = contents.get_object()
        cms_obj: cms.ContentInfo = cms.ContentInfo.load(encoded_data=sig_obj)
        signed_data: cms.SignedData = cms_obj["content"]
        signer_info: cms.SignerInfo = signed_data["signer_infos"][0]
        signed_attrs: cms.CMSAttributes = signer_info["signed_attrs"]
        hash_algorithm: HashAlgorithm = HashAlgorithm(signer_info["digest_algorithm"]["algorithm"].native)
        signature: bytes = signer_info["signature"].native
        signature_algorithm: str = signer_info["signature_algorithm"]["algorithm"].native

        # extract and validate the payload hash
        computed_hash: bytes = _cms_verify_payload_hash(signed_attrs=signed_attrs,
                                                        payload=payload,
                                                        hash_alg=hash_algorithm,
                                                        errors=curr_errors,
                                                        logger=logger)
        if curr_errors:
            break

        # extract the certificate chain and the signer's certificate proper
        cert_data: tuple[list[bytes], int] = _cms_build_cert_chain(signed_data=signed_data,
                                                                   signer_info=signer_info)
        cert_chain: list[bytes] = cert_data[0]
        cert_ord: int = cert_data[1]
        signer_cert: x509.Certificate = x509.load_der_x509_certificate(data=cert_chain[cert_ord])
        public_key: PublicKeyTypes = signer_cert.public_key()
        signature_padding: padding.AsymmetricPadding = \
            _crypto_get_signature_padding(public_key=public_key,
                                          signature_alg=signature_algorithm,
                                          hash_alg=hash_algorithm)
        # identify signer
        subject: x509.name.Name = signer_cert.subject
        signer_cn: str = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

        # verify the signature
        # ('errors' is not passed, as an invalid signature is not an error in the current context)
        if not _crypto_verify_signature(public_key=public_key,
                                        signature=signature,
                                        signature_padding=signature_padding,
                                        signer_cn=signer_cn,
                                        signed_attrs=signed_attrs,
                                        payload_hash=computed_hash,
                                        hash_algorithm=hash_algorithm,
                                        errors=None,
                                        logger=logger):
            result = False

    if not curr_errors and not sig_fields:
        msg: str = "No digital signatures found in PDF file"
        if logger:
            logger.error(msg=msg)
        curr_errors.append(msg)

    if curr_errors:
        result = None
        if isinstance(errors, list):
            errors.extend(curr_errors)
    elif result and logger:
        logger.debug(msg="Signature verification successful")

    return result
