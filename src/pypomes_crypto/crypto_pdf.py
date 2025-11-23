from __future__ import annotations
import base64
import sys
from asn1crypto import cms, tsp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO, StringIO
from logging import Logger
from pathlib import Path
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.signers import sign_pdf, PdfSigner, SimpleSigner, PdfSignatureMetadata
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.stamp import TextStampStyle
from pyhanko.sign.timestamps import HTTPTimeStamper
from PyPDF2 import PdfReader
from PyPDF2.generic import ArrayObject, ByteStringObject, DictionaryObject, Field
from pypomes_core import TZ_LOCAL, file_get_data, exc_format
from requests.auth import HTTPBasicAuth
from typing import Any, Literal

from .crypto_common import HashAlgorithm, ChpHash, ChpPublicKey, _chp_hash


class CryptoPdf:
    """
    Python code to extract crypto data from a *PAdES* compliant, digitally signed, PDF file.

    This is the only instance variable, used to hold the crypto data of the document's signatures :
    - signatures: list of *SignatureInfo*
    """
    # class-level logger
    logger: Logger | None = None

    @dataclass(frozen=True)
    class SignatureInfo:
        """
        These are the attributes holding the signature data.
        """
        payload_range: tuple[int, int, int, int]  # the range of bytes comprising the payload
        payload_hash: bytes                       # the payload hash
        hash_algorithm: HashAlgorithm             # the algorithm used to calculate the payload hash
        signature: bytes                          # the digital signature
        signature_algorithm: str                  # the algorithm used to generate the signature
        signature_timestamp: datetime             # the signature's timestamp
        public_key: ChpPublicKey                  # the public key (most likely, RSAPublicKey)
        cert_chain: list[bytes]                   # the serialized X509 certificate chain (in DER format)
        signer_cert: x509.Certificate             # the reference certificate (latest one in the chain)
        cert_serial_number: int                   # the certificate's serial nmumber
        signer_common_name: str                   # the name of the certificate's signer
        cert_issuer_name: str                     # the name of the certificate's issuer
        cert_fingerprint: str                     # the certificate's fingerprint

        # TSA (Tme Stamping Authority) data
        tsa_timestamp: datetime                   # the signature's timestamp
        tsa_policy: str                           # the TSA's policy
        tsa_serial_number: str                    # the timestamping's serial number
        tsa_fingerprint: str                      # the timestamping's fingerprint

    def __init__(self,
                 pdf_data: Path | str | bytes,
                 pdf_pwd: str = None,
                 errors: list[str] = None) -> None:
        """
        Instantiate the *CryptoPdf* class, and extract the relevant crypto data.

        The nature of *pdf_data* depends on its data type:
          - type *bytes*: *pdf_data* holds the data (used as is)
          - type *str*: *pdf_data* holds the data (used as utf8-encoded)
          - type *Path*: *pdf_data* is a path to a file holding the data

        If *pdf_data* is encrypted, the decryption password must be provided in *pdf_pwd*.
        For additional security, fingerprints in *SHA256* are calculated for every certificate
        in the certificate chain.

        :param pdf_data: a digitally signed, *PAdES* cxonformant, PDF file
        :param pdf_pwd: optional password for file decryption
        :param errors: incidental errors (may be non-empty)
        """
        # initialize the structure holding the crypto data
        self.signatures: list[CryptoPdf.SignatureInfo] = []

        # retrieve the PDF data
        self.pdf_bytes: bytes = file_get_data(file_data=pdf_data)

        # define a local errors list
        curr_errors: list[str] = []

        pdf_stream: BytesIO = BytesIO(initial_bytes=self.pdf_bytes)
        pdf_stream.seek(0)

        # retrieve the signature fields
        reader: PdfReader = PdfReader(stream=pdf_stream,
                                      password=pdf_pwd)
        sig_fields: list[Field] = [field for field in reader.get_fields().values()
                                   if field.get("/FT") == "/Sig"] or []

        # process the signature fields
        for sig_field in sig_fields:
            sig_dict: DictionaryObject = sig_field.get("/V")
            contents: ByteStringObject = sig_dict.get("/Contents")

            # extract the payload
            byte_range: ArrayObject = sig_dict.get("/ByteRange")
            from_1, len_1, from_2, len_2 = byte_range
            payload_range: tuple[int, int, int, int] = (int(from_1), int(len_1), int(from_2), int(len_2))
            payload: bytes = self.pdf_bytes[from_1:from_1+len_1] + self.pdf_bytes[from_2:from_2+len_2]

            # extract signature data (CMS structure)
            sig_obj: ByteStringObject = contents.get_object()
            cms_obj: cms.ContentInfo = cms.ContentInfo.load(encoded_data=sig_obj)
            signed_data: cms.SignedData = cms_obj["content"]
            signer_info: cms.SignerInfo = signed_data["signer_infos"][0]

            # extract the signature and its algorithms
            signature: bytes = signer_info["signature"].native
            signature_algorithm: str = signer_info["signature_algorithm"]["algorithm"].native
            alg_name: str = signer_info["digest_algorithm"]["algorithm"].native
            hash_algorithm: HashAlgorithm = HashAlgorithm(alg_name)

            # extract signature timestamp and payload hash
            chp_hash: ChpHash = _chp_hash(alg=hash_algorithm)
            payload_hash: bytes | None = None
            signature_timestamp: datetime | None = None
            if "signed_attrs" in signer_info:
                signed_attrs: cms.CMSAttributes = signer_info["signed_attrs"]
                for signed_attr in signed_attrs:
                    attr_type: str = signed_attr["type"].native
                    match attr_type:
                        case "message_digest":
                            payload_hash = signed_attr["values"][0].native
                        case "signing_time":
                            signature_timestamp = signed_attr["values"][0].native
            # validate hash
            from .crypto_pomes import crypto_hash
            effective_hash: bytes = crypto_hash(msg=payload,
                                                alg=hash_algorithm)
            if not payload_hash:
                payload_hash = effective_hash
            elif payload_hash != effective_hash:
                msg: str = f"Invalid digest for signature timestamp '{signature_timestamp}'"
                if CryptoPdf.logger:
                    CryptoPdf.logger.error(msg=msg)
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
            serial_number: int = signer_cert.serial_number
            cert_fingerprint: str = signer_cert.fingerprint(chp_hash).hex()

            # identify signer and issuer
            subject: x509.name.Name = signer_cert.subject
            signer_common_name: str = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            cert_issuer: x509.name.Name = signer_cert.issuer
            issuer_name: str = cert_issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

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
                        if CryptoPdf.logger:
                            msg: str = exc_format(exc=e,
                                                  exc_info=sys.exc_info())
                            CryptoPdf.logger.error(msg=msg)
                    break

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
                if CryptoPdf.logger:
                    msg: str = exc_format(exc=e,
                                          exc_info=sys.exc_info()) + f" signed by {signer_common_name}"
                    CryptoPdf.logger.warning(msg=msg)

            # build the signature's crypto data and save it
            sig_info: CryptoPdf.SignatureInfo = CryptoPdf.SignatureInfo(
                payload_range=payload_range,
                payload_hash=payload_hash,
                hash_algorithm=hash_algorithm,
                signature=signature,
                signature_algorithm=signature_algorithm,
                signature_timestamp=signature_timestamp,
                public_key=public_key,
                cert_chain=cert_chain,
                signer_cert=signer_cert,
                cert_serial_number=serial_number,
                signer_common_name=signer_common_name,
                cert_issuer_name=issuer_name,
                cert_fingerprint=cert_fingerprint,
                tsa_timestamp=tsa_timestamp,
                tsa_policy=tsa_policy,
                tsa_serial_number=tsa_serial_number,
                tsa_fingerprint=tsa_fingerprint
            )
            self.signatures.append(sig_info)

        if not curr_errors and not self.signatures:
            msg: str = "No digital signatures found in PDF file"
            if CryptoPdf.logger:
                CryptoPdf.logger.error(msg=msg)
            curr_errors.append(msg)

        if curr_errors and isinstance(errors, list):
            errors.extend(curr_errors)

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
        sig_info: CryptoPdf.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
        return sig_info.payload_hash \
            if fmt == "bytes" else base64.b64encode(s=sig_info.payload_hash).decode(encoding="utf-8")

    def get_signature(self,
                      fmt: Literal["base64", "bytes"],
                      sig_seq: int = 0) -> str | bytes:
        """
        Retrieve the signature associated with a reference signature, as specified in *sig_seq* and *fmt*.

        The natural ordering of the signatures in a *PAdES* compliant, digitally signed, PDF file is the
        chronological *latest-first* order. The value of *sig_seq* is subtracted from the ordinal position
        of the last signature in the signatures list, to yield the ordinal position of the reference signature.
        It defaults to *0*, indicating the latest signature. If the operation yields a number out of the range
        of available signatures, the latest signature is selected.

        :param fmt: the format to use
        :param sig_seq: the relative ordinal position of the reference signature
        :return: the signature, as per *fmt* (Base64-encoded or raw bytes)
        """
        sig_info: CryptoPdf.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
        return sig_info.signature \
            if fmt == "bytes" else base64.b64encode(s=sig_info.signature).decode(encoding="utf-8")

    def get_public_key(self,
                       fmt: Literal["base64", "der", "pem"],
                       sig_seq: int = 0) -> str | bytes:
        """
        Retrieve the public key associated with a reference signature, as specified in *sig_seq* and *fmt*.

        The natural ordering of the signatures in a *PAdES* compliant, digitally signed, PDF file is the
        chronological *latest-first* order. The value of *sig_seq* is subtracted from the ordinal position
        of the last signature in the signatures list, to yield the ordinal position of the reference signature.
        It defaults to *0*, indicating the latest signature. If the operation yields a number out of the range
        of available signatures, the latest signature is selected.

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

        sig_info: CryptoPdf.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
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

    def get_metadata(self,
                     sig_seq: int = 0) -> dict[str, Any]:
        """
        Retrieve the certificate chain metadata associated with a reference signature, as specified in *sig_seq*.

        The natural ordering of the signatures in a *PAdES* compliant, digitally signed, PDF file is the
        chronological *latest-first* order. The value of *sig_seq* is subtracted from the ordinal position
        of the last signature in the signatures list, to yield the ordinal position of the reference signature.
        It defaults to *0*, indicating the latest signature. If the operation yields a number out of the range
        of available signatures, the latest signature is selected.

        :param sig_seq: the relative ordinal position of the reference signature
        :return: the certificate chain metadata associated with the reference signature
        """
        # initialize the return variable
        result: dict[str, Any]

        sig_info: CryptoPdf.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
        cert: x509.Certificate = sig_info.signer_cert

        # compute fingerprints for the entire certificate chain
        chain_fingerprints: list[str] = []
        for cert_bytes in sig_info.cert_chain:
            chain_cert: x509.Certificate = x509.load_der_x509_certificate(data=cert_bytes,
                                                                          backend=default_backend())
            chp_hash: ChpHash = _chp_hash(alg=sig_info.hash_algorithm)
            chain_fingerprints.append(chain_cert.fingerprint(chp_hash).hex())

        result: dict[str, Any] = {
            "signer_common_name": sig_info.signer_common_name,
            "issuer": sig_info.cert_issuer_name,
            "hash_algorithm": sig_info.hash_algorithm,
            "signature_algorithm": sig_info.signature_algorithm,
            "signature_timestamp": sig_info.signature_timestamp.isoformat()
            if sig_info.signature_timestamp else None,
            "cert_serial_number": hex(sig_info.cert_serial_number),
            "cert_not_before": cert.not_valid_before.isoformat(),
            "cert_not_after": cert.not_valid_after.isoformat(),
            "cert_subject": cert.subject.rfc4514_string(),
            "cert_issuer": cert.issuer.rfc4514_string(),
            "cert_fingerprint": sig_info.cert_fingerprint,
            "cert_chain_length": len(sig_info.cert_chain),
            "cert_chain_fingerprints": chain_fingerprints
        }
        # add the TSA details
        if sig_info.tsa_fingerprint:
            result.update({
                "tsa_timestamp": sig_info.tsa_timestamp.isoformat()
                if sig_info.tsa_timestamp else None,
                "tsa_policy": sig_info.tsa_policy,
                "tsa_serial_number": sig_info.tsa_serial_number,
                "tsa_fingerprint": sig_info.tsa_fingerprint
            })

        return result

    def __get_sig_info(self,
                       sig_seq: int) -> CryptoPdf.SignatureInfo:
        """
        Retrieve the signature metadata of a reference signature, as specified in *sig_seq*.

        The natural ordering of the signatures in a *PAdES* compliant, digitally signed, PDF file is the
        chronological *latest-first* order. The value of *sig_seq* is subtracted from the ordinal position
        of the last signature in the signatures list, to yield the ordinal position of the reference signature.
        It defaults to *0*, indicating the latest signature. If the operation yields a number out of the range
        of available signatures, the latest signature is selected.

        :param sig_seq: the relative ordinal position of the reference signature
        :return: the reference signature's metadata

        """
        sig_ordinal: int = len(self.signatures) - 1
        if sig_seq <= sig_ordinal:
            sig_ordinal -= sig_seq

        return self.signatures[sig_ordinal]

    @staticmethod
    def set_logger(logger: Logger) -> None:
        """
        Configure the logger to be used in this module's operations.

        :param logger: the operations logger
        """
        CryptoPdf.logger = logger

    @staticmethod
    def create(pdf_in: Path | str,
               pfx_file: Path | str,
               pfx_password: str,
               pdf_out: Path | str = None,
               make_visible: bool = False,
               page_num: int = 0,
               box: tuple[int, int, int, int] = (50, 50, 250, 150),
               reason: str = None,
               location: str = None,
               tsa_url: str = None,
               tsa_username: str = None,
               tsa_password: str = None) -> CryptoPdf:
        """
        Digitally sign a PDF file in PAdES format using an A1 certificate.

        Supports visible signature appearance and TSA timestamping.

        :param pdf_in: path to the input PDF file
        :param pfx_file: path to the PKCS#12 (.pfx/.p12) certificate file
        :param pfx_password: password for the certificate
        :param pdf_out: path to the output signed PDF file (optional, no output if not provided)
        :param make_visible: whether to include a visible signature appearance
        :param page_num: page number for the visible signature (0-based)
        :param box: (x1, y1, x2, y2) coordinates for the signature box
        :param reason: reason for signing
        :param location: location of signing
        :param tsa_url: TSA server URL for timestamping
        :param tsa_username: TSA username (if required)
        :param tsa_password: TSA password (if required)
        :return: the corresponding instance of *CryptoPdf*, or *None* if error
        """
        # make sure 'pfx_file' is a 'Path'
        pfx_file = Path(pfx_file)
        # load the signing certificate and key from a PKCS#12 file
        simple_signer: SimpleSigner = SimpleSigner.load_pkcs12(pfx_file=pfx_file,
                                                               passphrase=pfx_password)
        # cconfigure stamp style if visible
        stamp_style: TextStampStyle | None = None
        new_field_spec: SigFieldSpec | None = None
        if make_visible:
            stamp_text: str = f"Signed by {simple_signer.subject_name}"
            if reason:
                stamp_text += f"\nReason: {reason}"
            if location:
                stamp_text += f"\nLocation: {location}"
            stamp_text += f"\nDate: {datetime.now(tz=TZ_LOCAL)}"
            stamp_style = TextStampStyle(stamp_text=stamp_text)
            new_field_spec = SigFieldSpec(sig_field_name="Signature1",
                                          box=box,
                                          on_page=page_num)
        # signature metadata
        sig_metadata = PdfSignatureMetadata(reason=reason, location=location, field_name="Signature1")
        # create PdfSigner with stamp_style
        pdf_signer: PdfSigner = PdfSigner(signer=simple_signer,
                                          signature_meta=sig_metadata,
                                          stamp_style=stamp_style)
        # configure TSA
        timestamper: HTTPTimeStamper | None = None
        if tsa_url:
            auth: HTTPBasicAuth | None = None
            if tsa_username and tsa_password:
                auth = HTTPBasicAuth(username=tsa_username,
                                     password=tsa_password)
            timestamper = HTTPTimeStamper(url=tsa_url,
                                          auth=auth,
                                          timeout=None)
        # make sure 'pdf_in' is a 'Path'
        pdf_in = Path(pdf_in)
        with pdf_in.open("rb") as in_f:
            # prepare the PDF for signing
            writer = IncrementalPdfFileWriter(in_f)
            # sign the PDF
            output_buf: StringIO = sign_pdf(pdf_out=writer,
                                            signer=pdf_signer,
                                            signature_meta=sig_metadata,
                                            new_field_spec=new_field_spec,
                                            timestamper=timestamper)
        signed_pdf: str = output_buf.read()

        # output the signed PDF
        if pdf_out:
            # make sure 'pdf_out' is a 'Path'
            pdf_out = Path(pdf_out)
            # write the signed PDF to a file
            with pdf_out.open("wt") as out_f:
                out_f.write(signed_pdf)

        return CryptoPdf(pdf_data=signed_pdf)
