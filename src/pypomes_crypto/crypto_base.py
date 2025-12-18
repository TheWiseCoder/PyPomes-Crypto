from __future__ import annotations  # allow forward references
import base64
from asn1crypto import pem
from datetime import datetime
from dataclasses import dataclass
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from io import BytesIO
from logging import Logger
from pathlib import Path
from pypomes_core import file_get_data
from typing import Any, Literal

from .crypto_common import HashAlgorithm


class CryptoBase:
    """
    Abstract base class for extracting crypto data from a digitally signed file.

    The crypto data follows the *Cryptographic Message Syntax* (CMS), a standard for digitally signing,
    digesting, authenticating, and encrypting arbitrary message content.

    These are the instance variables:
        - signatures: list of *SignatureInfo*, holds the crypto data of the document's signatures
        - p7x_bytes: the PKCS#7-compliant data in *DER* format
        - payload_bytes: the payload
    """
    # class-level logger
    logger: Logger | None = None

    @dataclass(frozen=True)
    class SignatureInfo:
        """
        These are the attributes holding the signature data.
        """
        payload_ranges: list[tuple[int, int]]     # the range of bytes comprising the payload
        payload_hash: bytes                       # the payload hash
        hash_algorithm: HashAlgorithm             # the algorithm used to calculate the payload hash
        signature: bytes                          # the digital signature
        signature_algorithm: str                  # the algorithm used to generate the signature
        signature_timestamp: datetime             # the signature's timestamp
        public_key: PublicKeyTypes                # the public key (most likely, RSAPublicKey)
        signer_cn: str                            # the common name of the certificate's signer
        signer_cert: x509.Certificate             # the reference certificate (latest one in the chain)
        cert_sn: int                              # the certificate's serial nmumber
        cert_chain: list[bytes]                   # the serialized X509 certificate chain (in DER format)

        # TSA (Time Stamping Authority) data
        tsa_timestamp: datetime                   # the signature's timestamp
        tsa_policy: str                           # the TSA's policy
        tsa_sn: str                               # the timestamping's serial number

    def __init__(self,
                 doc_in: BytesIO | Path | str | bytes | None,
                 p7x_in: BytesIO | Path | str | bytes | None) -> None:
        """
        Instantiate the subclass, for further extraction of the relevant crypto data.

        The nature of *p7x_in* and *doc_in* depends on its data type:
            - type *BytesIO*: is a byte stream
            - type *Path*: is a path to a file holding the data
            - type *bytes*: holds the data (used as is)
            - type *str*: holds the data (used as utf8-encoded)

        :param doc_in: the input document data
        :param p7x_in: the PKCS#7 input data in *DER* or *PEM* format
        """
        # initialize the instance variables
        self.signatures: list[CryptoBase.SignatureInfo] = []
        self.p7x_bytes: bytes | None = None
        self.payload_bytes: bytes | None = None

        # retrieve the PKCS#7 file data (if PEM, convert to DER)
        if p7x_in:
            self.p7x_bytes = file_get_data(file_data=p7x_in)
            if pem.detect(self.p7x_bytes):
                _, _, self.p7x_bytes = pem.unarmor(pem_bytes=self.p7x_bytes)

        # retrieve the input doc file data
        if doc_in:
            self.payload_bytes = file_get_data(file_data=doc_in)

    def get_digest(self,
                   fmt: Literal["base64", "bytes"],
                   sig_seq: int = 0) -> str | bytes:
        """
        Retrieve the digest associated with a reference signature, as specified in *sig_seq* and *fmt*.

        The natural ordering of the signatures in a *PAdES* compliant, digitally signed, PDF file is the
        chronological *latest-first* order. The value of *sig_seq* is subtracted from the ordinal position
        of the last signature in the signatures list, to yield the ordinal position of the reference signature.
        It defaults to *0*, indicating the latest signature. If the operation yields a number out of the range
        of available signatures, the latest signature is selected.

        :param fmt: the format to use
        :param sig_seq: the relative ordinal position of the reference signature
        :return: the digest, as per *fmt* (Base64-encoded or raw bytes)
        """
        sig_info: CryptoBase.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
        return sig_info.payload_hash \
            if fmt == "bytes" else base64.b64encode(s=sig_info.payload_hash).decode(encoding="utf-8")

    def get_payload(self,
                    sig_seq: int = 0) -> bytes:
        """
        Retrieve the payload associated with a reference signature, as specified in *sig_seq*.

        The natural order of the signatures in a PKCS#7 compliant file is the chronological *latest-first* order.
        The value of *sig_seq* is subtracted from the ordinal position of the last signature in the signatures list,
        to yield the ordinal position of the reference signature. It defaults to *0*, indicating the latest signature.
        If the operation yields a number out of the range of available signatures, the latest signature is selected.

        :param sig_seq: the relative ordinal position of the reference signature
        :return: the reference signature's payload
        """
        # initialize the return variable
        result: bytes = b""

        # add the individual ranges
        sig_info: CryptoBase.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
        for curr_range in sig_info.payload_ranges:
            result += self.payload_bytes[curr_range[0]:curr_range[1]]

        return result

    def get_signature(self,
                      fmt: Literal["base64", "bytes"],
                      sig_seq: int = 0) -> str | bytes:
        """
        Retrieve the signature associated with a reference signature, as specified in *sig_seq* and *fmt*.

        The natural order of the signatures in a PKCS#7 compliant file is the chronological *latest-first* order.
        The value of *sig_seq* is subtracted from the ordinal position of the last signature in the signatures list,
        to yield the ordinal position of the reference signature. It defaults to *0*, indicating the latest signature.
        If the operation yields a number out of the range of available signatures, the latest signature is selected.

        :param fmt: the format to use
        :param sig_seq: the relative ordinal position of the reference signature
        :return: the signature, as per *fmt* (Base64-encoded or raw bytes)
        """
        sig_info: CryptoBase.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
        return sig_info.signature \
            if fmt == "bytes" else base64.b64encode(s=sig_info.signature).decode(encoding="utf-8")

    def get_public_key(self,
                       fmt: Literal["base64", "der", "pem"],
                       sig_seq: int = 0) -> str | bytes:
        """
        Retrieve the public key associated with a reference signature, as specified in *sig_seq* and *fmt*.

        The natural order of the signatures in a PKCS#7 compliant file is the chronological *latest-first* order.
        The value of *sig_seq* is subtracted from the ordinal position of the last signature in the signatures list,
        to yield the ordinal position of the reference signature. It defaults to *0*, indicating the latest signature.
        If the operation yields a number out of the range of available signatures, the latest signature is selected.

        These are the supported formats:
            - *der*: the raw binary representation of the key
            - *pem*: the Base64-encoded key with headers and line breaks
            - *base64*: the Base64-encoded DER bytes

        :param fmt: the format to use
        :param sig_seq: the relative ordinal position of the reference signature
        :return: the public key, as per *fmt* (*str* or *bytes*)
        """
        # declare the return variable
        result: str | bytes

        sig_info: CryptoBase.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
        if fmt == "pem":
            result = sig_info.public_key.public_bytes(encoding=Encoding.PEM,
                                                      format=PublicFormat.SubjectPublicKeyInfo)
            result = result.decode(encoding="utf-8")
        else:
            result = sig_info.public_key.public_bytes(encoding=Encoding.DER,
                                                      format=PublicFormat.SubjectPublicKeyInfo)
            if fmt == "base64":
                result = base64.b64encode(s=result).decode(encoding="utf-8")

        return result

    def get_cert_chain(self,
                       sig_seq: int = 0) -> list[bytes]:
        """
        Retrieve the certificate chain associated with a reference signature, as specified in *sig_seq*.

        The natural order of the signatures in a PKCS#7 compliant file is the chronological *latest-first* order.
        The value of *sig_seq* is subtracted from the ordinal position of the last signature in the signatures list,
        to yield the ordinal position of the reference signature. It defaults to *0*, indicating the latest signature.
        If the operation yields a number out of the range of available signatures, the latest signature is selected.

        :param sig_seq: the relative ordinal position of the reference signature
        :return: the signature, as per *fmt* (Base64-encoded or raw bytes)
        """
        sig_info: CryptoBase.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
        return sig_info.cert_chain

    def get_metadata(self,
                     sig_seq: int = 0) -> dict[str, Any]:
        """
        Retrieve the certificate chain metadata associated with a reference signature, as specified in *sig_seq*.

        The natural order of the signatures in a PKCS#7 compliant file is the chronological *latest-first* order.
        The value of *sig_seq* is subtracted from the ordinal position of the last signature in the signatures list,
        to yield the ordinal position of the reference signature. It defaults to *0*, indicating the latest signature.
        If the operation yields a number out of the range of available signatures, the latest signature is selected.

        :param sig_seq: the relative ordinal position of the reference signature
        :return: the certificate chain metadata associated with the reference signature
        """
        # declare the return variable
        result: dict[str, Any]

        sig_info: CryptoBase.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
        cert: x509.Certificate = sig_info.signer_cert

        result: dict[str, Any] = {
            "signer-cn": sig_info.signer_cn,
            "hash-algorithm": sig_info.hash_algorithm,
            "signature-algorithm": sig_info.signature_algorithm,
            "signature-timestamp": sig_info.signature_timestamp,
            "cert-sn": sig_info.cert_sn,
            "cert-not-before": cert.not_valid_before,
            "cert-not-after": cert.not_valid_after,
            "cert-subject": cert.subject.rfc4514_string(),
            "cert-issuer": cert.issuer.rfc4514_string(),
            "cert-chain-length": len(sig_info.cert_chain)
        }
        # add the TSA details
        if sig_info.tsa_sn:
            result.update({
                "tsa-timestamp": sig_info.tsa_timestamp,
                "tsa-policy": sig_info.tsa_policy,
                "tsa-sn": sig_info.tsa_sn
            })

        return result

    def __get_sig_info(self,
                       sig_seq: int) -> CryptoBase.SignatureInfo:
        """
        Retrieve the signature metadata of a reference signature, as specified in *sig_seq*.

        The natural order of the signatures in a PKCS#7 compliant file is the chronological *latest-first* order.
        The value of *sig_seq* is subtracted from the ordinal position of the last signature in the signatures list,
        to yield the ordinal position of the reference signature. It defaults to *0*, indicating the latest signature.
        If the operation yields a number out of the range of available signatures, the latest signature is selected.

        :param sig_seq: the relative ordinal position of the reference signature
        :return: the reference signature's metadata

        """
        sig_ordinal: int = max(-1, len(self.signatures) - sig_seq - 1)
        return self.signatures[sig_ordinal]
