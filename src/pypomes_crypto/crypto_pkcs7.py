from __future__ import annotations  # allow forward references
import base64
import sys
from asn1crypto import cms, core, pem, tsp, x509 as asn1crypto_x509
from datetime import datetime
from dataclasses import dataclass
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, pkcs7, pkcs12
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from io import BytesIO
from logging import Logger
from pathlib import Path
from pypomes_core import file_get_data, exc_format
from typing import Any, Literal

from .crypto_common import (
    CRYPTO_DEFAULT_HASH_ALGORITHM,
    HashAlgorithm, SignatureType, ChpHash, _chp_hash
)


class CryptoPkcs7:
    """
    Python code to extract crypto data from a PKCS#7 signature file.

    The crypto data is in *Cryptographic Message Syntax* (CMS), a standard for digitally signing, digesting,
    authenticating, andr encrypting arbitrary message content.

    These are the instance attributes:
        - p7s_bytes: bytes                 - the PKCS#7-compliant data in *DER* format
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
        signer_common_name: str             # the name of the certificate's signer
        signer_cert: x509.Certificate       # the reference certificate (latest one in the chain)
        cert_serial_number: int             # the certificate's serial nmumber
        cert_chain: list[bytes]             # the serialized X509 certificate chain (in DER format)

        # TSA (Time Stamping Authority) data
        tsa_timestamp: datetime             # the signature's timestamp
        tsa_policy: str                     # the TSA's policy
        tsa_serial_number: str              # the timestamping's serial number

    def __init__(self,
                 p7s_in: BytesIO | Path | str | bytes,
                 doc_in: BytesIO | Path | str | bytes = None,
                 errors: list[str] = None) -> None:
        """
        Instantiate the *CryptoPkcs7* class, and extract the relevant crypto data.

        The natures of *p7s_in* and *doc_in* depend on their respective data types:
          - type *BytesIO*: is a byte stream
          - type *Path*: is a path to a file holding the data
          - type *str*: holds the data (used as utf8-encoded)
          - type *bytes*: holds the data (used as is)

        The PKCS#7 data provided in *p7s_data* contains the A1 certificate and its corresponding
        public key, the certificate chain, the original payload (if *attached* mode), and the
        digital signature. The latter is always validated, and if a payload is specified in
        *doc_data* (*detached* mode), it is validated against its declared hash value.

        :param p7s_in: the PKCS#7 data in *DER* or *PEDM* format
        :param doc_in: the original document data (the payload, required in detached mode)
        :param errors: incidental errors
        """
        # declare/initialize the instance variables
        self.signatures: list[CryptoPkcs7.SignatureInfo] = []
        self.payload: bytes | None = None
        self.p7s_bytes: bytes

        # retrieve the PKCS#7 file data (if PEM, convert to DER)
        self.p7s_bytes = file_get_data(file_data=p7s_in)
        if pem.detect(self.p7s_bytes):
            _, _, self.p7s_bytes = pem.unarmor(pem_bytes=self.p7s_bytes)

        # define a local errors list
        curr_errors: list[str] = []

        # extract the base CMS structure
        signed_data: cms.SignedData | None = None
        try:
            content_info = cms.ContentInfo.load(encoded_data=self.p7s_bytes)
            if content_info["content_type"].native == "signed_data":
                signed_data = content_info["content"]
            else:
                msg = "'p7_data' does not hold a valid PKCS#7 file"
                if CryptoPkcs7.logger:
                    CryptoPkcs7.logger.error(msg=msg)
                curr_errors.append(msg)
        except Exception as e:
            msg: str = exc_format(exc=e,
                                  exc_info=sys.exc_info())
            if CryptoPkcs7.logger:
                CryptoPkcs7.logger.error(msg=msg)
            curr_errors.append(msg)

        if not curr_errors:
            # signatures in PKCS#7 are parallel, not chained, so they share the same payload
            encap_content: core.OctetString = signed_data["encap_content_info"]["content"]
            if encap_content:
                # attached mode
                self.payload = encap_content.native
            elif doc_in:
                # detached mode
                self.payload = file_get_data(file_data=doc_in)
            if not self.payload:
                msg = "For detached mode, a payload file must be provided"
                if CryptoPkcs7.logger:
                    CryptoPkcs7.logger.error(msg=msg)
                curr_errors.append(msg)

        if not curr_errors:
            # traverse the list of signatures
            signer_infos: list[cms.SignerInfo] = signed_data["signer_infos"]
            for signer_info in signer_infos:

                # extract the signature and its algorithms
                signature_bytes: bytes = signer_info["signature"].native
                signature_alg_name: str = signer_info["signature_algorithm"]["algorithm"].native
                digest_alg_name: str = signer_info["digest_algorithm"]["algorithm"].native
                hash_algorithm: HashAlgorithm = HashAlgorithm(digest_alg_name)

                stored_hash: bytes | None = None
                signature_timestamp: datetime | None = None
                signed_attrs: cms.CMSAttributes = signer_info["signed_attrs"] or []
                for signed_attr in signed_attrs:
                    attr_type: str = signed_attr["type"].native
                    match attr_type:
                        case "message_digest":
                            stored_hash = signed_attr["values"][0].native
                        case "signing_time":
                            signature_timestamp = signed_attr["values"][0].native

                # obtain/validate the hash
                from .crypto_pomes import crypto_hash
                computed_hash: bytes = crypto_hash(msg=self.payload,
                                                   alg=hash_algorithm)
                if not stored_hash:
                    if CryptoPkcs7.logger:
                        CryptoPkcs7.logger.warning(msg="'p7s_data' has no stored payload digest")
                    stored_hash = computed_hash
                elif computed_hash != stored_hash:
                    msg = "Computed and stored digest values do not match"
                    if CryptoPkcs7.logger:
                        CryptoPkcs7.logger.error(msg=msg)
                    curr_errors.append(msg)
                    break

                # select the correct certificate while building the certificate chain
                signer_id: cms.SignerIdentifier = signer_info["sid"]
                signer_cert_bytes: bytes | None = None
                cert_chain: list[bytes] = []
                certs: cms.CertificateSet = signed_data["certificates"]
                for cert_choice in certs:
                    # HAZARD: 'cert' is not a 'cryptography.x509.Certificate' object
                    cert: asn1crypto_x509.Certificate = cert_choice.chosen
                    der_bytes: bytes = cert.dump()
                    cert_chain.append(der_bytes)
                    if signer_cert_bytes is None:
                        if signer_id.name == "issuer_and_serial_number":
                            # match issuer and serial number
                            if cert.issuer == signer_id.chosen["issuer"] and \
                               cert.serial_number == signer_id.chosen["serial_number"].native:
                                signer_cert_bytes = der_bytes
                        elif signer_id.name == "subject_key_identifier":
                            # extract SKI from certificate extensions
                            for ext in cert["tbs_certificate"]["extensions"]:
                                if ext["extn_id"].native == "subject_key_identifier" and \
                                        ext["extn_value"].native == signer_id.chosen.native:
                                    signer_cert_bytes = der_bytes
                                    break

                # extract public key serial number
                signer_cert: x509.Certificate = x509.load_der_x509_certificate(data=cert_chain[0])
                public_key: PublicKeyTypes = signer_cert.public_key()
                cert_serial_number: int = signer_cert.serial_number

                # identify the signer
                subject: x509.name.Name = signer_cert.subject
                signer_common_name: str = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

                # TSA timestamp info (optional)
                tsa_timestamp: datetime | None = None
                tsa_policy: str | None = None
                tsa_serial_number: str | None = None

                unsigned_attrs: cms.CMSAttributes = signer_info["unsigned_attrs"]
                for unsigned_attr in unsigned_attrs:
                    attr_type: str = unsigned_attr["type"].native
                    if attr_type == "signature_time_stamp_token":
                        try:
                            # the timestamp token is a CMS SignedData structure -'dump()' gets the raw DER bytes
                            values: cms.SetOfContentInfo = unsigned_attr["values"]
                            timestamp_token: cms.ContentInfo = cms.ContentInfo.load(values[0].dump())

                            # extract the TSTInfo structure
                            tst_signed_data: cms.SignedData = timestamp_token["content"]
                            tst_info: tsp.TSTInfo = tst_signed_data["encap_content_info"]["content"].parsed

                            # extract TSA timestamp details
                            tsa_timestamp = tst_info["gen_time"].native
                            tsa_policy = tst_info["policy"].native
                            tsa_serial_number = hex(tst_info["serial_number"].native)

                        except Exception as e:
                            # unable to obtain TAS data: error parsing token
                            if CryptoPkcs7.logger:
                                msg: str = exc_format(exc=e,
                                                      exc_info=sys.exc_info())
                                CryptoPkcs7.logger.warning(msg=msg)
                        break

                # verify the signature
                if signed_attrs:
                    # HAZARD:
                    #   - when 'signed_attrs' exists, the signature covers its attributes, not the raw data
                    #   - 'signed_attrs' was sorted in DER canonical order before it was signed
                    #   - 'signed_attrs' was kept stored in the insert order of its attributes
                    #   - 'dump()' fails to apply the DER canonical sort to 'signed_attrs'
                    #   - a manual sort to 'signed_attrs' is thus required, for the verification to succeed
                    sorted_attrs: list[cms.CMSAttribute] = sorted(signed_attrs,
                                                                  key=lambda attr: attr.dump())
                    signed_attrs = cms.CMSAttributes(sorted_attrs)
                    computed_hash = crypto_hash(msg=signed_attrs.dump(),
                                                alg=hash_algorithm)

                chp_hash: ChpHash = _chp_hash(alg=hash_algorithm)
                try:
                    if isinstance(public_key, rsa.RSAPublicKey):
                        # determine the signature padding used
                        if "pss" in signature_alg_name:
                            signature_padding: padding.AsymmetricPadding = padding.PSS(
                                mgf=padding.MGF1(algorithm=chp_hash),
                                salt_length=padding.PSS.MAX_LENGTH
                            )
                        else:
                            signature_padding: padding.AsymmetricPadding = padding.PKCS1v15()

                        public_key.verify(signature=signature_bytes,
                                          data=computed_hash,
                                          padding=signature_padding,
                                          algorithm=Prehashed(chp_hash))
                    else:
                        public_key.verify(signature=signature_bytes,
                                          data=computed_hash,
                                          algorithm=Prehashed(chp_hash))
                except Exception as e:
                    if CryptoPkcs7.logger:
                        msg: str = exc_format(exc=e,
                                              exc_info=sys.exc_info())
                        CryptoPkcs7.logger.warning(msg=msg + f" signed by {signer_common_name}")

                # build the signature's crypto data and save it
                sig_info: CryptoPkcs7.SignatureInfo = CryptoPkcs7.SignatureInfo(
                    payload_hash=stored_hash,
                    hash_algorithm=hash_algorithm,
                    signature=signature_bytes,
                    signature_algorithm=signature_alg_name,
                    signature_timestamp=signature_timestamp,
                    public_key=public_key,
                    signer_common_name=signer_common_name,
                    signer_cert=signer_cert,
                    cert_serial_number=cert_serial_number,
                    cert_chain=cert_chain,
                    tsa_timestamp=tsa_timestamp,
                    tsa_policy=tsa_policy,
                    tsa_serial_number=tsa_serial_number
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
            "signer-common-name": sig_info.signer_common_name,
            "hash-algorithm": sig_info.hash_algorithm,
            "signature-algorithm": sig_info.signature_algorithm,
            "signature-timestamp": sig_info.signature_timestamp,
            "cert-serial-number": sig_info.cert_serial_number,
            "cert-not-before": cert.not_valid_before,
            "cert-not-after": cert.not_valid_after,
            "cert-subject": cert.subject.rfc4514_string(),
            "cert-issuer": cert.issuer.rfc4514_string(),
            "cert-chain-length": len(sig_info.cert_chain)
        }
        # add the TSA details
        if sig_info.tsa_serial_number:
            result.update({
                "tsa-timestamp": sig_info.tsa_timestamp,
                "tsa-policy": sig_info.tsa_policy,
                "tsa-serial-number": sig_info.tsa_serial_number
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
             p7s_out: BytesIO | Path | str = None,
             embed_attrs: bool = True,
             hash_alg: HashAlgorithm = CRYPTO_DEFAULT_HASH_ALGORITHM,
             sig_type: SignatureType = SignatureType.DETACHED,
             errors: list[str] = None) -> CryptoPkcs7:
        """
        Digitally sign a file in *attached* or *detached* format, using an A1 certificate.

        The natures of *doc_in* and *pfx_in* depend on their respective data types:
          - type *BytesIO*: is a byte stream
          - type *Path*: is a path to a file holding the data
          - type *str*: holds the data (used as utf8-encoded)
          - type *bytes*: holds the data (used as is)

        The signature is created as a PKCS#7/CMS compliant structure with full certificate chain.
        The parameter *sig_mode* determines whether the payload is to be embedded (*attached*),
        or left aside (*detached*).

        The parameter *embed_attrs* determines whether authenticated attributes should be embedded in the
         PKCS#7 structure (defaults to *True*). These are the attributes grouped under the label "signed_attrs",
         that are cryptographically signed by the signer, meaning that, when they exist, the signature covers
         them, rather than the raw data. Besides the ones standardized in *RFC* publications, custom attributes
         may be created and given *OID* (Object Identifier) codes, to include application-specific metadata.
         These are some common *signed_attrs*:
            - *commitment_type_indication*: indicates the type of commitment (e.g., proof of origin)
            - *content_hint*: provides a hint about the content type or purpose
            - *content_type*: indicates the type of the signed content (e.g., *data*, *signedData*, *envelopedData*)
            - *message_digest*: contains the hash (digest) of the content being signed
            - *signer_location*: specifies the geographic location of the signer
            - *signing_certificate*: identifies the certificate used for signing
            - *signing_time: the UTC time at which the signature was generated
            - *smime_capabilities*": lists the cryptographic capabilities supported by the signer

        :param doc_in: the document to sign
        :param pfx_in: the PKCS#12 (*.pfx*) data, containing A1 certificate and private key
        :param pfx_pwd: password for the *.pfx* data (if not provided, *pfx_in* is assumed to be unencrypted)
        :param p7s_out: path to the output PKCS#7 file (optional, no output if not provided)
        :param embed_attrs: whether to embed the authenticated attributes in the PKCS#7 structure (defaults to *True*)
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
            result = CryptoPkcs7(p7s_in=pkcs7_data,
                                 doc_in=doc_bytes if sig_type == SignatureType.DETACHED else None,
                                 errors=curr_errors)

            # output the PKCS#7 file
            if not curr_errors and p7s_out:
                if isinstance(p7s_out, str):
                    p7s_out = Path(p7s_out)
                if isinstance(p7s_out, Path):
                    # write the PKCS#7 data to a file
                    with p7s_out.open("wb") as out_f:
                        out_f.write(pkcs7_data)
                else:  # isinstance(p7s_out, BytesIO)
                    # stream the PKCS#7 data to a file
                    p7s_out.write(pkcs7_data)

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
