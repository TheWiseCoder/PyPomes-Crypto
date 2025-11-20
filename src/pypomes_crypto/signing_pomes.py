import base64
from asn1crypto import cms, pem
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7Options, PKCS7SignatureBuilder
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography import x509
from logging import Logger
from pathlib import Path
from pypomes_core import file_get_data
from typing import Any, Literal

from .crypto_pomes import (
    CRYPTO_DEFAULT_HASH_ALGORITHM, HashAlgorithm, SignatureMode, crypto_hash
)

CryptographyHashes = hashes.SHA224 | hashes.SHA256 | hashes.SHA384 | hashes.SHA512


def crypto_sign_document(doc_data: Path | str | bytes,
                         p12_data: Path | str | bytes,
                         cert_pwd: str | bytes,
                         hash_alg: HashAlgorithm = CRYPTO_DEFAULT_HASH_ALGORITHM,
                         sig_mode: SignatureMode = SignatureMode.DETACHED,
                         sig_format: Literal["base64", "der", "pem"]  = "base64",
                         errors: list[str] = None,
                         logger: Logger = None) -> str | bytes | None:
    """
    Digitally sign a document using a type A1 certificate (*.pfx*) and return the signature.

    The nature of *doc_data* and *p12_data* depend on their respective data types:
      - type *bytes*: holds the data (used as is)
      - type *str*: holds the data (used as utf8-encoded)
      - type *Path*: is a path to a file holding the data

    The signature is returned as a PKCS#7/CMS conformant structure with full certificate chain,
    and support for DER, Base64, or PEM formats. The parameter *sig_mode* indicates whether the
    signature is returned embedded with the payload (*attached*), or by itself (*detached*).

    :param doc_data: the document to sign
    :param p12_data: the PKCS#12 (*.pfx*) data, containing A1 certificate and private key
    :param cert_pwd: password for the *.pfx* data
    :param hash_alg: the algorithm for hashing
    :param sig_mode: the signature mode ("attached" or "detached" - defaults to "detached")
    :param sig_format: "base64", "der", or "pem" (defaults to "base64")
    :param errors: incidental errors
    :param logger: optional logger
    :return: the PKCS#7 signature, as per *sig_format* (*bytes* or *str*), or *None* if error
    """
    # initialize the return variable
    result: str | bytes | None = None

    # retrieve the document and certificate raw bytes
    doc_bytes: bytes = file_get_data(file_data=doc_data)
    p12_bytes: bytes = file_get_data(file_data=p12_data)

    # load A1 certificate and private key from the raw certificate data
    pwd_bytes = cert_pwd.encode() if isinstance(cert_pwd, str) else cert_pwd
    cert_data: tuple = load_key_and_certificates(data=p12_bytes,
                                                 password=pwd_bytes)
    private_key: PrivateKeyTypes = cert_data[0]
    cert_main: x509.Certificate = cert_data[1]
    additional_certs: list[x509.Certificate] = cert_data[2] or []

    err_msg: str | None = None
    if cert_main and private_key:
        # prepare the PKCS#7 builder
        sig_hasher: CryptographyHashes = __cryptography_hash(hash_alg=hash_alg,
                                                             errors=errors,
                                                             logger=logger)
        if sig_hasher:
            builder: PKCS7SignatureBuilder = PKCS7SignatureBuilder().set_data(data=doc_bytes)
            builder = builder.add_signer(certificate=cert_main,
                                         private_key=private_key,
                                         hash_algorithm=sig_hasher)

            # add full certificate chain to the return data
            for cert in additional_certs:
                builder = builder.add_certificate(cert)

            # define PKCS#7 options
            options: list[PKCS7Options] = [PKCS7Options.Binary]
            if sig_mode.DETACHED:
                options.append(PKCS7Options.DetachedSignature)

            # create PKCS#7 signature in DER format
            pkcs7_signature: bytes = builder.sign(encoding=serialization.Encoding.DER,
                                                  options=options)
            # handle the return format
            match sig_format:
                case "base64":
                    result = base64.b64encode(s=pkcs7_signature).decode(encoding="ascii")
                case "pem":
                    pem_data: bytes = pem.armor(type_name="PKCS7",
                                                der_bytes=pkcs7_signature)
                    result = pem_data.decode()
                case _:  # "der"
                    result = pkcs7_signature
    elif cert_main:
        err_msg = "Failed to load the private key"
    else:
        err_msg = "Failed to load the digital certificate"

    if err_msg:
        if logger:
            logger.error(msg=err_msg)
        if isinstance(errors, list):
            errors.append(err_msg)

    return result


def verify_signature(p7s_data: Path | str | bytes,
                     doc_data: Path | str | bytes,
                     sig_format: Literal["base64", "der", "pem"]  = "base64",
                     errors: list[str] = None,
                     logger: Logger = None) -> bool | None:
    """
    Verify a PKCS#7 signature against a document.

    The nature of *doc_data* and *p7s_data* depend on their respective data types:
      - type *bytes*: holds the data (used as is)
      - type *str*: holds the data (used as utf8-encoded)
      - type *Path*: is a path to a file holding the data

    Both attached and detached signatures are properly handled, and full cryptographic verification
    (digest + RSA signature check) is performed.

    :param p7s_data: the PKCS#7 signature data containing A1 certificate
    :param doc_data: the original document data (required for detached mode)
    :param sig_format: "base64", "der", or "pem" (defaults to "base64")
    :param errors: incidental errors
    :param logger: optional logger
     :return: *True* if signature is valid, *False* otherwise, or *None* if error
    """
    # initialize the return variable
    result: bool | None = None

    # retrieve the certificate raw bytes
    p7_bytes: bytes = file_get_data(file_data=p7s_data)

    # Load signature bytes
    sig_bytes: bytes
    match sig_format:
        case "base64":
            sig_bytes: bytes = base64.b64decode(s=p7_bytes.decode(encoding="utf-8"))
        case "pem":
            _, _, sig_bytes = pem.unarmor(p7_bytes)
        case _:  # "der"
            sig_bytes = p7_bytes

    # parse the CMS structure
    err_msg: str | None = None
    signed_data: dict[str, Any] |  None = None
    content_to_verify: bytes | None = None
    content_info = cms.ContentInfo.load(encoded_data=sig_bytes)
    if content_info["content_type"].native == "signed_data":
        signed_data = content_info["content"]
        embedded_content: bytes = signed_data["encap_content_info"]["content"].native

        # determine attached vs detached
        if embedded_content:
            # attached mode: use embedded content for digest
            content_to_verify = embedded_content
        else:
            # detached mode: use external document
            content_to_verify = file_get_data(file_data=doc_data)
            if not content_to_verify:
                err_msg = "No payload found for sitgnature verification"
    else:
        err_msg = "'p7_data' is not a SignedData PKCS#7 structure"

    if not err_msg:
        # compute the digest
        hash_alg: str = signed_data["signer_infos"][0]["digest_algorithm"]["algorithm"].native
        sig_hasher: CryptographyHashes = __cryptography_hash(hash_alg=HashAlgorithm(hash_alg),
                                                             errors=errors,
                                                             logger=logger) \
            if hash_alg in HashAlgorithm  else None

        if sig_hasher:
            computed_digest: bytes = crypto_hash(msg=content_to_verify,
                                                 alg=HashAlgorithm(hash_alg))
            # extract the signer info
            signer_info = signed_data["signer_infos"][0]
            signature_bytes = signer_info["signature"].native

            # extract certificate
            cert_data = signed_data["certificates"][0].chosen.dump()
            cert = x509.load_der_x509_certificate(cert_data)
            public_key = cert.public_key()

            # Verify signature using RSA + PKCS#1 v1.5
            try:
                public_key.verify(signature=signature_bytes,
                                  data=computed_digest,
                                  padding=padding.PKCS1v15(),
                                  algorithm=sig_hasher
                )
                result = True
                if logger:
                    logger.debug(msg="Signature verification successful")
            except Exception as e:
                result = False
                if logger:
                    logger.debug(msg=f"Signature verification failed: {e}")
    if err_msg:
        if logger:
            logger.error(msg=err_msg)
        if isinstance(errors, list):
            errors.append(err_msg)

    return result


def __cryptography_hash(hash_alg: HashAlgorithm,
                        errors: list[str] = None,
                        logger: Logger = None) -> CryptographyHashes:
    """
    Construct the *Crypto* package's hash object corresponding top *hash_alg*.

    :param hash_alg: the hash algorithm
    :payload: the
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
