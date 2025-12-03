from __future__ import annotations  # allow forward references
import base64
from asn1crypto import cms, pem
from datetime import datetime
from dataclasses import dataclass
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, pkcs7, pkcs12
from io import BytesIO
from logging import Logger
from pathlib import Path
from pypomes_core import file_get_data
from typing import Any, Literal

from .crypto_common import (
    CRYPTO_DEFAULT_HASH_ALGORITHM,
    HashAlgorithm, SignatureType, ChpHash,
    _chp_hash, _cms_build_cert_chain, _cms_verify_payload_hash,
    _cms_get_attr_value, _cms_get_content_info, _cms_get_payload, _cms_get_tsa_info,
    _crypto_get_signature_padding, _crypto_verify_signature
)


class CryptoPkcs7:
    """
    Python code to extract crypto data from a PKCS#7 signature file.

    The crypto data is in *Cryptographic Message Syntax* (CMS), a standard for digitally signing, digesting,
    authenticating, andr encrypting arbitrary message content.

    These are the instance attributes:
        - p7x_bytes: bytes                 - the PKCS#7-compliant data in *DER* format
        - payload: bytes                   - the common payload (embedded or external)
        - signatures: list[SignatureInfo]  - data for list of signatures
    """
    # class-level logger
    logger: Logger | None = None

    @dataclass(frozen=True)
    class SignatureInfo:
        """
        These are the attributes holding the signature data.
        """
        payload_hash: bytes                 # the payload hash
        hash_algorithm: HashAlgorithm       # the algorithm used to calculate the payload hash
        signature: bytes                    # the digital signature
        signature_algorithm: str            # the algorithm used to generate the signature
        signature_timestamp: datetime       # the signature's timestamp
        public_key: PublicKeyTypes          # the public key (most likely, RSAPublicKey)
        signer_cn: str                      # the common name of the certificate's signer
        signer_cert: x509.Certificate       # the reference certificate (latest one in the chain)
        cert_sn: int                        # the certificate's serial nmumber
        cert_chain: list[bytes]             # the serialized X509 certificate chain (in DER format)

        # TSA (Time Stamping Authority) data
        tsa_timestamp: datetime             # the signature's timestamp
        tsa_policy: str                     # the TSA's policy
        tsa_sn: str                         # the timestamping's serial number

    def __init__(self,
                 p7x_in: BytesIO | Path | str | bytes,
                 doc_in: BytesIO | Path | str | bytes = None,
                 errors: list[str] = None) -> None:
        """
        Instantiate the *CryptoPkcs7* class, and extract the relevant crypto data.

        The natures of *p7x_in* and *doc_in* depend on their respective data types:
            - type *BytesIO*: is a byte stream
            - type *Path*: is a path to a file holding the data
            - type *bytes*: holds the data (used as is)
            - type *s'tr*: holds the data (used as utf8-encoded)

        The PKCS#7 data provided in *p7s_in* contains the A1 certificate and its corresponding
        public key, the certificate chain, the original payload (if *attached* mode), and the
        digital signature. The latter is always validated, and if a payload is provided in
        *doc_in* (*detached* mode), it is validated against its declared hash value.

        :param p7x_in: the PKCS#7 data in *DER* or *PEDM* format
        :param doc_in: the original document data (the payload, required in *detached* mode)
        :param errors: incidental errors
        """
        # declare/initialize the instance variables
        self.signatures: list[CryptoPkcs7.SignatureInfo] = []
        self.payload: bytes | None = None
        self.p7s_bytes: bytes

        # retrieve the PKCS#7 file data (if PEM, convert to DER)
        self.p7s_bytes = file_get_data(file_data=p7x_in)
        if pem.detect(self.p7s_bytes):
            _, _, self.p7s_bytes = pem.unarmor(pem_bytes=self.p7s_bytes)

        # define a local errors list
        curr_errors: list[str] = []

        # extract the base CMS structure-
        content_info: cms.ContentInfo = _cms_get_content_info(p7s_bytes=self.p7s_bytes,
                                                              errors=curr_errors,
                                                              logger=CryptoPkcs7.logger)
        signed_data: cms.SignedData = content_info["content"] if content_info else None
        signer_infos: cms.SignerInfos | None = None
        if signed_data:
            # signatures in PKCS#7 are parallel, not chained, so they share the same payload
            self.payload = _cms_get_payload(signed_data=signed_data,
                                            doc_in=doc_in,
                                            errors=curr_errors,
                                            logger=CryptoPkcs7.logger)
            signer_infos: cms.SignerInfos = signed_data["signer_infos"]

        # process the signatures
        for signer_info in (signer_infos or []):

            # extract the signature data
            signed_attrs: cms.CMSAttributes = signer_info["signed_attrs"]
            hash_algorithm: HashAlgorithm = HashAlgorithm(signer_info["digest_algorithm"]["algorithm"].native)
            signature: bytes = signer_info["signature"].native
            signature_algorithm: str = signer_info["signature_algorithm"]["algorithm"].native
            signature_timestamp: datetime = _cms_get_attr_value(cms_attrs=signed_attrs,
                                                                attr_type="signing_time")
            # extract and validate the payload hash
            computed_hash: bytes = _cms_verify_payload_hash(signed_attrs=signed_attrs,
                                                            payload=self.payload,
                                                            hash_alg=hash_algorithm,
                                                            errors=curr_errors,
                                                            logger=CryptoPkcs7.logger)
            if curr_errors:
                break

            # extract the certificate chain and the signer's certificate proper
            cert_data: tuple[list[bytes], int] = _cms_build_cert_chain(signed_data=signed_data,
                                                                       signer_info=signer_info)
            cert_chain: list[bytes] = cert_data[0]
            cert_ord: int = cert_data[1]
            signer_cert: x509.Certificate = x509.load_der_x509_certificate(data=cert_chain[cert_ord])
            public_key: PublicKeyTypes = signer_cert.public_key()
            cert_serial_number: int = signer_cert.serial_number
            signature_padding: padding.AsymmetricPadding = \
                _crypto_get_signature_padding(public_key=public_key,
                                              signature_alg=signature_algorithm,
                                              hash_alg=hash_algorithm)
            # identify the signer
            subject: x509.name.Name = signer_cert.subject
            signer_cn: str = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

            # TSA timestamp info (optional)
            tsa_data: tuple[datetime, str, str] = _cms_get_tsa_info(signer_info=signer_info,
                                                                    logger=CryptoPkcs7.logger)
            tsa_timestamp: datetime = tsa_data[0]
            tsa_policy: str = tsa_data[1]
            tsa_sn: str = tsa_data[2]

            # verify the signature
            _crypto_verify_signature(public_key=public_key,
                                     signature=signature,
                                     signature_padding=signature_padding,
                                     signer_cn=signer_cn,
                                     signed_attrs=signed_attrs,
                                     payload_hash=computed_hash,
                                     hash_algorithm=hash_algorithm,
                                     errors=curr_errors,
                                     logger=CryptoPkcs7.logger)
            if curr_errors:
                break

            # build the signature's crypto data and save it
            sig_info: CryptoPkcs7.SignatureInfo = CryptoPkcs7.SignatureInfo(
                payload_hash=computed_hash,
                hash_algorithm=hash_algorithm,
                signature=signature,
                signature_algorithm=signature_algorithm,
                signature_timestamp=signature_timestamp,
                public_key=public_key,
                signer_cn=signer_cn,
                signer_cert=signer_cert,
                cert_sn=cert_serial_number,
                cert_chain=cert_chain,
                tsa_timestamp=tsa_timestamp,
                tsa_policy=tsa_policy,
                tsa_sn=tsa_sn
            )
            self.signatures.append(sig_info)

        if curr_errors and isinstance(errors, list):
            errors.extend(curr_errors)

    def get_digest(self,
                   fmt: Literal["base64", "bytes"],
                   sig_seq: int = 0) -> str | bytes:
        """
        Retrieve the digest associated with a reference signature, as specified in *sig_seq* and *fmt*.

        The natural ordering of the signatures in a *PKCS#7* compliant *.p7s* file is the chronological
        *latest-first* order. The value of *sig_seq* is subtracted from the ordinal position of the last
        signature in the signatures list, to yield the ordinal position of the reference signature.
        It defaults to *0*, indicating the latest signature. If the operation yields a number out of
        the range of available signatures, the latest signature is selected.

        :param fmt: the format to use
        :param sig_seq: the relative ordinal position of the reference signature
        :return: the digest, as per *fmt* (Base64-encoded or raw bytes)
        """
        sig_info: CryptoPkcs7.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
        return sig_info.payload_hash \
            if fmt == "bytes" else base64.b64encode(s=sig_info.payload_hash).decode(encoding="utf-8")

    def get_signature(self,
                      fmt: Literal["base64", "bytes"],
                      sig_seq: int = 0) -> str | bytes:
        """
        Retrieve the signature associated with a reference signature, as specified in *sig_seq* and *fmt*.

        The natural ordering of the signatures in a *PKCS#7* compliant *.p7s* file is the chronological
        *latest-first* order. The value of *sig_seq* is subtracted from the ordinal position of the last
        signature in the signatures list, to yield the ordinal position of the reference signature.
        It defaults to *0*, indicating the latest signature. If the operation yields a number out of
        the range of available signatures, the latest signature is selected.

        :param fmt: the format to use
        :param sig_seq: the relative ordinal position of the reference signature
        :return: the signature, as per *fmt* (Base64-encoded or raw bytes)
        """
        sig_info: CryptoPkcs7.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
        return sig_info.signature \
            if fmt == "bytes" else base64.b64encode(s=sig_info.signature).decode(encoding="utf-8")

    def get_public_key(self,
                       fmt: Literal["base64", "der", "pem"],
                       sig_seq: int = 0) -> str | bytes:
        """
        Retrieve the public key associated with a reference signature, as specified in *sig_seq* and *fmt*.

        The natural ordering of the signatures in a *PKCS#7* compliant *.p7s* file is the chronological
        *latest-first* order. The value of *sig_seq* is subtracted from the ordinal position of the last
        signature in the signatures list, to yield the ordinal position of the reference signature.
        It defaults to *0*, indicating the latest signature. If the operation yields a number out of
        the range of available signatures, the latest signature is selected.

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

        sig_info: CryptoPkcs7.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
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

        The natural ordering of the signatures in a *PKCS#7* compliant *.p7s* file is the chronological
        *latest-first* order. The value of *sig_seq* is subtracted from the ordinal position of the last
        signature in the signatures list, to yield the ordinal position of the reference signature.
        It defaults to *0*, indicating the latest signature. If the operation yields a number out of
        the range of available signatures, the latest signature is selected.

        :param sig_seq: the relative ordinal position of the reference signature
        :return: the signature, as per *fmt* (Base64-encoded or raw bytes)
        """
        sig_info: CryptoPkcs7.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
        return sig_info.cert_chain

    def get_metadata(self,
                     sig_seq: int = 0) -> dict[str, Any]:
        """
        Retrieve the certificate chain metadata associated with a reference signature, as specified in *sig_seq*.

        The natural ordering of the signatures in a *PKCS#7* compliant *.p7s* file is the chronological
        *latest-first* order. The value of *sig_seq* is subtracted from the ordinal position of the last
        signature in the signatures list, to yield the ordinal position of the reference signature.
        It defaults to *0*, indicating the latest signature. If the operation yields a number out of
        the range of available signatures, the latest signature is selected.

        :param sig_seq: the relative ordinal position of the reference signature
        :return: the certificate chain metadata associated with the reference signature
        """
        # declare the return variable
        result: dict[str, Any]

        sig_info: CryptoPkcs7.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
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
                       sig_seq: int) -> CryptoPkcs7.SignatureInfo:
        """
        Retrieve the signature metadata of a reference signature, as specified in *sig_seq*.

        The natural ordering of the signatures in a *PKCS#7* compliant *.p7s* file is the chronological
        *latest-first* order. The value of *sig_seq* is subtracted from the ordinal position of the last
        signature in the signatures list, to yield the ordinal position of the reference signature.
        It defaults to *0*, indicating the latest signature. If the operation yields a number out of
        the range of available signatures, the latest signature is selected.

        :param sig_seq: the relative ordinal position of the reference signature
        :return: the reference signature's metadata

        """
        sig_ordinal: int = max(-1, len(self.signatures) - sig_seq - 1)
        return self.signatures[sig_ordinal]

    @staticmethod
    def sign(doc_in: BytesIO | Path | str | bytes,
             pfx_in: BytesIO | Path | str | bytes,
             pfx_pwd: str | bytes = None,
             p7x_out: BytesIO | Path | str = None,
             embed_attrs: bool = True,
             hash_alg: HashAlgorithm = CRYPTO_DEFAULT_HASH_ALGORITHM,
             sig_type: SignatureType = SignatureType.DETACHED,
             errors: list[str] = None) -> CryptoPkcs7 | None:
        """
        Digitally sign a file in *attached* or *detached* format, using an A1 certificate.

        The natures of *doc_in* and *pfx_in* depend on their respective data types:
          - type *BytesIO*: is a byte stream
          - type *Path*: is a path to a file holding the data
          - type *bytes*: holds the data (used as is)
          - type *str*: holds the data (used as utf8-encoded)

        The signature is created as a PKCS#7/CMS compliant structure with full certificate chain.
        The parameter *sig_mode* determines whether the payload is to be embedded (*attached*),
        or left aside (*detached*).

        The parameter *embed_attrs* determines whether authenticated attributes should be embedded in the
        PKCS#7 structure (defaults to *True*). These are the attributes grouped under the label "signed_attrs"
        and cryptographically signed by the signer, meaning that, when they exist, the signature covers them,
        rather than the raw data. Besides the ones standardized in *RFC* publications, custom attributes
        may be created and given *OID* (Object Identifier) codes, to include application-specific metadata.
        These are some of the attributes:
            - *commitment_type_indication*: indicates the type of commitment (e.g., proof of origin)
            - *content_hint*: provides a hint about the content type or purpose
            - *content_type*: indicates the type of the signed content (e.g., *data*, *signedData*, *envelopedData*)
            - *message_digest*: contains the digest (usually, a SHA256 hash) of the payload (typically, *doc_in*)
            - *signer_location*: specifies the geographic location of the signer
            - *signing_certificate*: identifies the certificate used for signing
            - *signing_time*: the UTC time at which the signature was generated
            - *smime_capabilities*: lists the cryptographic capabilities supported by the signer

        If specified, *p7x_out* must be a *BytesIO* object, or contain a valid filepath. If the latter is
        provided without a file extension, it is set to *.p7m* or *.p7s*, depending on whether *sig_type*
        is specified as *attached* or *detached*, respectively. If the file already exists, it will be overwritten.

        :param doc_in: the document to sign
        :param pfx_in: the PKCS#12 (*.pfx*) data, containing A1 certificate and private key
        :param pfx_pwd: password for the *.pfx* data (if not provided, *pfx_in* is assumed to be unencrypted)
        :param p7x_out: path or byte stream to output the PKCS#7 file (optional, no output if not provided)
        :param embed_attrs: whether to embed the signed attributes in the PKCS#7 structure (defaults to *True*)
        :param hash_alg: the algorithm for hashing
        :param sig_type: whether to handle the payload as "attached" (defaults to "detached")
        :param errors: incidental errors (may be non-empty)
        :return: the instance of *CryptoPkcs7*, or *None* if error
        """
        # initialize the return variable
        result: CryptoPkcs7 | None = None

        # definal a local errors list
        curr_errors: list[str] = []

        # retrieve the document and certificate raw bytes
        doc_bytes: bytes = file_get_data(file_data=doc_in)
        pfx_bytes: bytes = file_get_data(file_data=pfx_in)

        # load A1 certificate and private key from the raw certificate data
        pwd_bytes = pfx_pwd.encode() if isinstance(pfx_pwd, str) else pfx_pwd
        cert_data: tuple = pkcs12.load_key_and_certificates(data=pfx_bytes,
                                                            password=pwd_bytes)
        private_key: PrivateKeyTypes = cert_data[0]
        cert_main: x509.Certificate = cert_data[1]
        sig_hasher: ChpHash = _chp_hash(alg=hash_alg,
                                        errors=curr_errors)

        if cert_main and private_key and sig_hasher:
            additional_certs: list[x509.Certificate] = cert_data[2] or []

            # prepare the PKCS#7 builder
            builder: pkcs7.PKCS7SignatureBuilder = pkcs7.PKCS7SignatureBuilder(data=doc_bytes)
            builder = builder.add_signer(certificate=cert_main,
                                         private_key=private_key,
                                         hash_algorithm=sig_hasher,
                                         rsa_padding=padding.PKCS1v15())
            # add full certificate chain to the return data
            for cert in additional_certs:
                builder = builder.add_certificate(cert)

            # define PKCS#7 options:
            #   - Binary: do not translate input data into canonical MIME format
            #   - DetachedSignature: do not embed data in the PKCS7 structure
            #   - NoAttributes: do not embed authenticated attributes (includes NoCapabilities)
            #   - NoCapabilities: do not embed SMIME capabilities
            #   - NoCerts: do not embed signer certificate
            #   - Text: add text/plain MIME type (requires DetachedSignature and Encoding.SMIME)
            options: list[pkcs7.PKCS7Options] = [pkcs7.PKCS7Options.Binary]
            if sig_type == SignatureType.DETACHED:
                options.append(pkcs7.PKCS7Options.DetachedSignature)
            if not embed_attrs:
                options.append(pkcs7.PKCS7Options.NoAttributes)

            # build the PKCS#7 data in DER format
            pkcs7_data: bytes = builder.sign(encoding=Encoding.DER,
                                             options=options)
            # instantiate the object
            doc_in: bytes = doc_bytes if sig_type == SignatureType.DETACHED else None
            crypto_pkcs7: CryptoPkcs7 = CryptoPkcs7(p7x_in=pkcs7_data,
                                                    doc_in=doc_in,
                                                    errors=curr_errors)
            if not curr_errors:
                result = crypto_pkcs7

                # output the PKCS#7 file
                if not curr_errors:
                    if isinstance(p7x_out, str):
                        p7x_out = Path(p7x_out)
                    if isinstance(p7x_out, Path):
                        # write the PKCS#7 data to a file
                        if not p7x_out.suffix:
                            suffix: str = ".p7m" if sig_type == SignatureType.ATTACHED else ".p7s"
                            p7x_out = p7x_out.with_suffix(suffix)
                        with p7x_out.open("wb") as out_f:
                            out_f.write(pkcs7_data)
                    elif isinstance(p7x_out, BytesIO):
                        # stream the PKCS#7 data to a file
                        p7x_out.write(pkcs7_data)

        elif not curr_errors:
            if not cert_main:
                msg: str = "Failed to load the digital certificate"
            else:
                msg: str = "Failed to load the private key"
            if CryptoPkcs7.logger:
                CryptoPkcs7.logger.error(msg=msg)
            curr_errors.append(msg)

        if curr_errors and isinstance(errors, list):
            errors.extend(curr_errors)

        return result

    @staticmethod
    def set_logger(logger: Logger) -> None:
        """
        Configure the logger to be used in this module's operations.

        :param logger: the operations logger
        """
        CryptoPkcs7.logger = logger
