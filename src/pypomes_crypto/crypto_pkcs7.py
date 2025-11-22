from __future__ import annotations  # allow forward references
import base64
import sys
from asn1crypto import cms
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    PKCS7Options, PKCS7SignatureBuilder, load_der_pkcs7_certificates
)
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from logging import Logger
from pathlib import Path
from pypomes_core import file_get_data, exc_format
from typing import Literal

from .crypto_pomes import crypto_hash
from .crypto_common import (
    CRYPTO_DEFAULT_HASH_ALGORITHM,
    SignatureMode, HashAlgorithm,
    CryptographyHashes, _cryptography_hash
)


class CryptoPkcs7:
    """
    Python code to extract crypto data from a PKCS#7 signature file.

    These are the instance attributes:
        - p7s_bytes: bytes              - the PKCS#7 data
        - payload: bytes                - the payload (embedded or external)
        - payload_hash: bytes           - the payload hash
        - hash_algorithm: HashAlgorithm - the algorithm used to calculate the payload hash
        - signature: bytes              - the digital signature
        - signature_algorithm: str      - the algorithm used to generate the signature
        - signature_timestamp: datetime - the signature's timestamp
        - public_key: RSAPublicKey      - the RSA public key
        - cert_chain: list[bytes]       - the serialized X509 certificate chain (in DER format)
    """

    logger: Logger | None = None

    def __init__(self,
                 p7s_data: Path | str | bytes,
                 doc_data: Path | str | bytes = None,
                 errors: list[str] = None) -> None:
        """
        Instantiate the *CryptoPkcs7* class, and extract the relevant crypto data.

        The natures of *p7s_data* and *doc_data* depend on their respective data types:
          - type *bytes*: holds the data (used as is)
          - type *str*: holds the data (used as utf8-encoded)
          - type *Path*: is a path to a file holding the data

        The PKCS#7 data provided in *p7s_data* contains the A1 certificate and its corresponding
        public key, the certificate chain, the original payload (if *attached* mode, only), and
        the digital signature. The latter is always validated, and if a payload is specified
        in *doc_data* (*detached* mode), it is validated against its declared hash value.

        :param p7s_data: the PKCS#7 data in DER (Distinguished Encoding Rules) format
        :param doc_data: the original document data (the payload, required in detached mode)
        :param errors: incidental errors
        """
        # obtain the PKCS#7 file data
        self.p7s_bytes: bytes = file_get_data(file_data=p7s_data)

        # extract the certificate chain and serialize it in DER format
        certs: list[x509.Certificate] = load_der_pkcs7_certificates(data=self.p7s_bytes)
        self.cert_chain: list[bytes] = [cert.public_bytes(encoding=Encoding.DER)
                                        for cert in certs]

        #  extract the public key and serialize it in DER format
        cert: x509.Certificate = certs[0]
        # 'cert.public_key()' may return one of:
        #   DSAPublicKey, RSAPublicKey, EllipticCurvePublicKey,
        #   Ed25519PublicKey, Ed448PublicKey, X25519PublicKey, X448PublicKey
        self.public_key: RSAPublicKey = cert.public_key()

        # extract the needed structures
        content_info: cms.ContentInfo = cms.ContentInfo.load(encoded_data=self.p7s_bytes)
        signed_data: cms.SignedData = content_info["content"]
        signer_info: cms.SignerInfo = signed_data["signer_infos"][0]

        # extract the needed components
        self.hash_algorithm: HashAlgorithm = HashAlgorithm(signer_info["digest_algorithm"]["algorithm"].native)
        self.signature: bytes = signer_info["signature"].native
        self.signature_algorithm: str = signer_info["signature_algorithm"]["algorithm"].native

        signed_attrs = signer_info["signed_attrs"]
        for signed_attr in signed_attrs:
            match signed_attr["type"].native:
                case "message_digest":
                    self.payload_hash: bytes = signed_attr["values"][0].native
                case "signing_time":
                    self.signature_timestamp: datetime = signed_attr["values"][0].native

        if doc_data:
            # payload is detached, load it and validate its hash
            self.payload: bytes = file_get_data(file_data=doc_data)
            effective_hash: bytes = crypto_hash(msg=self.payload,
                                                alg=self.hash_algorithm)
            if effective_hash != self.payload_hash:
                msg: str = "Invalid hash value in 'p7s_data'"
                if CryptoPkcs7.logger:
                    CryptoPkcs7.logger.error(msg=msg)
                if isinstance(errors, list):
                    errors.append(msg)
        else:
            # payload is attached, extract it
            self.payload: bytes = signed_data["encap_content_info"]["content"].native

        # validate the signature
        sig_hasher: CryptographyHashes = _cryptography_hash(hash_alg=self.hash_algorithm,
                                                            errors=errors)
        try:
            self.public_key.verify(signature=self.signature,
                                   data=self.payload_hash,
                                   padding=padding.PKCS1v15(),
                                   algorithm=sig_hasher)
        except Exception as e:
            msg = exc_format(exc=e,
                             exc_info=sys.exc_info())
            if CryptoPkcs7.logger:
                CryptoPkcs7.logger.error(msg=msg)
            if isinstance(errors, list):
                errors.append(msg)

    def get_digest(self,
                   fmt: Literal["base64", "bytes"]) -> str | bytes:
        """
        Retrieve the digest, as specified in *fmt*.

        :param fmt: the format to use
        :return: the digest, as per *fmt* (Base64-encoded or raw bytes)
        """
        return self.payload_hash \
            if fmt == "bytes" else base64.b64encode(s=self.payload_hash).decode(encoding="utf-8")

    def get_signature(self,
                      fmt: Literal["base64", "bytes"]) -> str | bytes:
        """
        Retrieve the signature, as specified in *fmt*.

        :param fmt: the format to use
        :return: the signature, as per *fmt* (Base64-encoded or raw bytes)
        """
        return self.signature \
            if fmt == "bytes" else base64.b64encode(s=self.signature).decode(encoding="utf-8")

    def get_public_key(self,
                       fmt: Literal["base64", "der", "pem"]) -> str | bytes:
        """
        Retrieve the public key, as specified in *fmt*.

        These are the supported formats:
            - *der*: the raw binary representation of the key
            - *pem*: the Base64-encoded key with headers and line breaks
            - *base64*: the Base64-encoded DER bytes

        :param fmt: the format to use
        :return: the public key, as per *fmt* (*str* or *bytes*)
        """
        # declare the return variable
        result: str | bytes

        if fmt == "pem":
            result = self.public_key.public_bytes(encoding=Encoding.PEM,
                                                  format=PublicFormat.SubjectPublicKeyInfo)
            result = result.decode(encoding="utf-8")
        else:
            result = self.public_key.public_bytes(encoding=Encoding.DER,
                                                  format=PublicFormat.SubjectPublicKeyInfo)
            if fmt == "base64":
                result = base64.b64encode(s=result).decode(encoding="utf-8")

        return result

    @staticmethod
    def create(doc_data: Path | str | bytes,
               p12_data: Path | str | bytes,
               cert_pwd: str | bytes,
               hash_alg: HashAlgorithm = CRYPTO_DEFAULT_HASH_ALGORITHM,
               sig_mode: SignatureMode = SignatureMode.DETACHED,
               errors: list[str] = None) -> CryptoPkcs7:
        """
        Instantiate a *CryptoPkcs7* object by signing a document with a type A1 certificate.

        The natures of *doc_data* and *p12_data* depend on their respective data types:
          - type *bytes*: holds the data (used as is)
          - type *str*: holds the data (used as utf8-encoded)
          - type *Path*: is a path to a file holding the data

        The signature is created as a PKCS#7/CMS conformant structure with full certificate chain.
        The parameter *sig_mode* determines whether the payload is to be embedded (*attached*),
        or left aside (*detached*).

        :param doc_data: the document to sign
        :param p12_data: the PKCS#12 (*.pfx*) data, containing A1 certificate and private key
        :param cert_pwd: password for the *.pfx* data
        :param hash_alg: the algorithm for hashing
        :param sig_mode: whether to handle the payload as "attached"(defaults to "detached")
        :param errors: incidental errors (may be non-empty)
        :return: the corresponding instance of *CryptoPkcs7*, or *None* if error
        """
        # initialize the return variable
        result: CryptoPkcs7 | None = None

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
            sig_hasher: CryptographyHashes = _cryptography_hash(hash_alg=hash_alg,
                                                                errors=errors)
            if sig_hasher:
                builder: PKCS7SignatureBuilder = PKCS7SignatureBuilder()
                builder = builder.set_data(data=doc_bytes)
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

                # build the PKCS#7 data in DER format
                pkcs7_data: bytes = builder.sign(encoding=Encoding.DER,
                                                 options=options)
                # instantiate the object
                if sig_mode.DETACHED:
                    result = CryptoPkcs7(p7s_data=pkcs7_data,
                                         doc_data=doc_bytes)
                else:
                    result = CryptoPkcs7(p7s_data=pkcs7_data)
        elif cert_main:
            err_msg = "Failed to load the private key"
        else:
            err_msg = "Failed to load the digital certificate"

        if err_msg:
            if CryptoPkcs7.logger:
                CryptoPkcs7.logger.error(msg=err_msg)
            if isinstance(errors, list):
                errors.append(err_msg)

        return result

    @staticmethod
    def set_logger(logger: Logger) -> None:
        """
        Configure the logger to be used in this module's operations.

        :param logger: the operations logger
        """
        CryptoPkcs7.logger = logger
