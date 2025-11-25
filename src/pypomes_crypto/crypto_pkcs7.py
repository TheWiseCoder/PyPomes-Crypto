from __future__ import annotations  # allow forward references
import base64
import sys
from asn1crypto import cms, core, tsp
from datetime import datetime
from dataclasses import dataclass
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    PKCS7Options, PKCS7SignatureBuilder
)
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from logging import Logger
from pathlib import Path
from pypomes_core import file_get_data, exc_format
from typing import Any, Literal

from .crypto_common import (
    CRYPTO_DEFAULT_HASH_ALGORITHM,
    SignatureMode, HashAlgorithm,
    ChpHash, ChpPublicKey, _chp_hash
)


class CryptoPkcs7:
    """
    Python code to extract crypto data from a PKCS#7 signature file.

    The crypto data is in *Cryptographic Message Syntax* (CMS), a standard for digitally signing, digesting,
    authenticating, andr encrypting arbitrary message content.

    These are the instance attributes:
        - p7s_bytes: bytes                 - the PKCS#7-compliant file
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
        public_key: ChpPublicKey            # the public key (most likely, RSAPublicKey)
        signer_common_name: str             # the name of the certificate's signer
        signer_cert: x509.Certificate       # the reference certificate (latest one in the chain)
        cert_serial_number: int             # the certificate's serial nmumber
        cert_fingerprint: str               # the certificate's fingerprint
        cert_chain: list[bytes]             # the serialized X509 certificate chain (in DER format)

        # TSA (Time Stamping Authority) data
        tsa_timestamp: datetime             # the signature's timestamp
        tsa_policy: str                     # the TSA's policy
        tsa_serial_number: str              # the timestamping's serial number
        tsa_fingerprint: str                # the timestamping's fingerprint

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
        public key, the certificate chain, the original payload (if *attached* mode), and the
        digital signature. The latter is always validated, and if a payload is specified in
        *doc_data* (*detached* mode), it is validated against its declared hash value.

        :param p7s_data: the PKCS#7 data in DER (Distinguished Encoding Rules) format
        :param doc_data: the original document data (the payload, required in detached mode)
        :param errors: incidental errors
        """
        # initialize the structure holding the crypto data
        self.signatures: list[CryptoPkcs7.SignatureInfo] = []

        # retrieve the PKCS#7 file data
        self.p7s_bytes: bytes = file_get_data(file_data=p7s_data)

        # definal a local errors list
        curr_errors: list[str] = []

        # extract the structures common to all signatures
        content_info: cms.ContentInfo = cms.ContentInfo.load(encoded_data=self.p7s_bytes)
        signed_data: cms.SignedData = content_info["content"]

        # signatures in PKCS#7 are parallel, not chained, so they share the same payload
        self.payload: bytes | None = None
        encap_content: core.OctetString = signed_data["encap_content_info"]["content"]
        if encap_content:
            # attached mode
            self.payload = encap_content.native
        elif doc_data:
            # detached mode
            self.payload = file_get_data(file_data=doc_data)

        if self.payload:
            # traverse the list of signatures
            signer_infos: list[cms.SignerInfo] = signed_data["signer_infos"]
            for signer_info in signer_infos:

                # extract the signature and its algorithms
                signature: bytes = signer_info["signature"].native
                signature_algorithm: str = signer_info["signature_algorithm"]["algorithm"].native
                alg_name: str = signer_info["digest_algorithm"]["algorithm"].native
                hash_algorithm: HashAlgorithm = HashAlgorithm(alg_name)
                chp_hash: ChpHash = _chp_hash(alg=hash_algorithm)

                payload_hash: bytes | None = None
                signature_timestamp: datetime | None = None
                signed_attrs: cms.CMSAttributes = signer_info["signed_attrs"] or []
                for signed_attr in signed_attrs:
                    attr_type: str = signed_attr["type"].native
                    match attr_type:
                        case "message_digest":
                            payload_hash: bytes = signed_attr["values"][0].native
                        case "signing_time":
                            signature_timestamp: datetime = signed_attr["values"][0].native

                # obtain/validate the hash
                from .crypto_pomes import crypto_hash
                effective_hash: bytes = crypto_hash(msg=self.payload,
                                                    alg=hash_algorithm)
                if not payload_hash:
                    payload_hash = effective_hash
                elif payload_hash != effective_hash:
                    msg: str = f"Invalid digest for signature timestamp '{signature_timestamp}'"
                    if CryptoPkcs7.logger:
                        CryptoPkcs7.logger.error(msg=msg)
                    curr_errors.append(msg)
                    break

                # build the certificate chain
                cert_chain: list[bytes] = []
                certs: cms.CertificateSet = signed_data["certificates"]
                for cert in certs:
                    der_bytes: bytes = cert.dump()
                    cert_chain.append(der_bytes)

                # extract certificates and public key
                signer_cert: x509.Certificate = x509.load_der_x509_certificate(data=cert_chain[0],
                                                                               backend=default_backend())
                public_key: ChpPublicKey = signer_cert.public_key()
                cert_serial_number: int = signer_cert.serial_number
                cert_fingerprint: str = signer_cert.fingerprint(chp_hash).hex()

                # identify signer
                subject: x509.name.Name = signer_cert.subject
                signer_common_name: str = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

                # TSA timestamp info (optional)
                tsa_timestamp: datetime | None = None
                tsa_policy: str | None = None
                tsa_serial_number: str | None = None
                tsa_fingerprint: str | None = None

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

                            # calculate the TSA certificate fingerprint
                            tsa_cert = signed_data["certificates"][0]
                            tsa_cert_bytes = tsa_cert.dump()
                            tsa_cert_obj = x509.load_der_x509_certificate(data=tsa_cert_bytes,
                                                                          backend=default_backend())
                            tsa_fingerprint: str = tsa_cert_obj.fingerprint(chp_hash).hex()
                        except Exception as e:
                            # unable to obtain TAS data: error parsing token
                            if CryptoPkcs7.logger:
                                msg: str = exc_format(exc=e,
                                                      exc_info=sys.exc_info())
                                CryptoPkcs7.logger.error(msg=msg)
                        break

                if payload_hash:
                    # verify the signature
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
                            public_key.verify(signature=signature,
                                              data=payload_hash,
                                              padding=signature_padding,
                                              algorithm=Prehashed(chp_hash))
                        else:
                            public_key.verify(signature=signature,
                                              data=payload_hash,
                                              algorithm=Prehashed(chp_hash))
                    except Exception as e:
                        if CryptoPkcs7.logger:
                            msg: str = exc_format(exc=e,
                                                  exc_info=sys.exc_info()) + f" signed by {signer_common_name}"
                            CryptoPkcs7.logger.warning(msg=msg)

                # build the signature's crypto data and save it
                sig_info: CryptoPkcs7.SignatureInfo = CryptoPkcs7.SignatureInfo(
                    payload_hash=payload_hash,
                    hash_algorithm=hash_algorithm,
                    signature=signature,
                    signature_algorithm=signature_algorithm,
                    signature_timestamp=signature_timestamp,
                    public_key=public_key,
                    signer_common_name=signer_common_name,
                    signer_cert=signer_cert,
                    cert_serial_number=cert_serial_number,
                    cert_fingerprint=cert_fingerprint,
                    cert_chain=cert_chain,
                    tsa_timestamp=tsa_timestamp,
                    tsa_policy=tsa_policy,
                    tsa_serial_number=tsa_serial_number,
                    tsa_fingerprint=tsa_fingerprint
                )
                self.signatures.append(sig_info)
        else:
            msg = "For detached mode, a payload file must be provided"
            if CryptoPkcs7.logger:
                CryptoPkcs7.logger.error(msg=msg)
            curr_errors.append(msg)

        if not curr_errors and not self.signatures:
            msg: str = "No digital signatures found in PKCS#7 file"
            if CryptoPkcs7.logger:
                CryptoPkcs7.logger.error(msg=msg)
            curr_errors.append(msg)

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
        Retrieve the certificate chain associated with a reference signature, as specified in *sig_seq**.

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

        # compute fingerprints for the entire certificate chain
        chain_fingerprints: list[str] = []
        for cert_bytes in sig_info.cert_chain:
            chain_cert: x509.Certificate = x509.load_der_x509_certificate(data=cert_bytes,
                                                                          backend=default_backend())
            chp_hash: ChpHash = _chp_hash(alg=sig_info.hash_algorithm)
            chain_fingerprints.append(chain_cert.fingerprint(chp_hash).hex())

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
            "cert-fingerprint": sig_info.cert_fingerprint,
            "cert-chain-length": len(sig_info.cert_chain),
            "cert-chain-fingerprints": chain_fingerprints
        }
        # add the TSA details
        if sig_info.tsa_fingerprint:
            result.update({
                "tsa-timestamp": sig_info.tsa_timestamp,
                "tsa-policy": sig_info.tsa_policy,
                "tsa-serial_number": sig_info.tsa_serial_number,
                "tsa-fingerprint": sig_info.tsa_fingerprint
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
    def create(doc_data: Path | str | bytes,
               pfx_data: Path | str | bytes,
               pfx_pwd: str | bytes,
               p7s_out: Path | str = None,
               hash_alg: HashAlgorithm = CRYPTO_DEFAULT_HASH_ALGORITHM,
               sig_mode: SignatureMode = SignatureMode.DETACHED,
               errors: list[str] = None) -> CryptoPkcs7:
        """
        Instantiate a *CryptoPkcs7* object by signing a document with a type A1 certificate.

        The natures of *doc_data* and *pfx_data* depend on their respective data types:
          - type *bytes*: holds the data (used as is)
          - type *str*: holds the data (used as utf8-encoded)
          - type *Path*: is a path to a file holding the data

        The signature is created as a PKCS#7/CMS compliant structure with full certificate chain.
        The parameter *sig_mode* determines whether the payload is to be embedded (*attached*),
        or left aside (*detached*).

        :param doc_data: the document to sign
        :param pfx_data: the PKCS#12 (*.pfx*) data, containing A1 certificate and private key
        :param pfx_pwd: password for the *.pfx* data
        :param p7s_out: path to the output PKCS#7 file (optional, no output if not provided)
        :param hash_alg: the algorithm for hashing
        :param sig_mode: whether to handle the payload as "attached"(defaults to "detached")
        :param errors: incidental errors (may be non-empty)
        :return: the corresponding instance of *CryptoPkcs7*, or *None* if error
        """
        # initialize the return variable
        result: CryptoPkcs7 | None = None

        # definal a local errors list
        curr_errors: list[str] = []

        # retrieve the document and certificate raw bytes
        doc_bytes: bytes = file_get_data(file_data=doc_data)
        pfx_bytes: bytes = file_get_data(file_data=pfx_data)

        # load A1 certificate and private key from the raw certificate data
        pwd_bytes = pfx_pwd.encode() if isinstance(pfx_pwd, str) else pfx_pwd
        cert_data: tuple = load_key_and_certificates(data=pfx_bytes,
                                                     password=pwd_bytes)
        private_key: PrivateKeyTypes = cert_data[0]
        cert_main: x509.Certificate = cert_data[1]
        additional_certs: list[x509.Certificate] = cert_data[2] or []

        if cert_main and private_key:
            # prepare the PKCS#7 builder
            sig_hasher: ChpHash = _chp_hash(alg=hash_alg,
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
                if sig_mode == SignatureMode.DETACHED:
                    options.append(PKCS7Options.DetachedSignature)

                # build the PKCS#7 data in DER format
                pkcs7_data: bytes = builder.sign(encoding=Encoding.DER,
                                                 options=options)
                # instantiate the object
                if sig_mode == SignatureMode.ATTACHED:
                    result = CryptoPkcs7(p7s_data=pkcs7_data,
                                         errors=curr_errors)
                else:
                    result = CryptoPkcs7(p7s_data=pkcs7_data,
                                         doc_data=doc_bytes,
                                         errors=curr_errors)
                # output the PKCS#7 file
                if not curr_errors and p7s_out:
                    # make sure 'p7s_out' is a 'Path'
                    p7s_out = Path(p7s_out)
                    # write the PKCS#7 data to a file
                    with p7s_out.open("wb") as out_f:
                        out_f.write(pkcs7_data)
        elif cert_main:
            msg = "Failed to load the private key"
            if CryptoPkcs7.logger:
                CryptoPkcs7.logger.error(msg=msg)
            curr_errors.append(msg)
        else:
            msg = "Failed to load the digital certificate"
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
