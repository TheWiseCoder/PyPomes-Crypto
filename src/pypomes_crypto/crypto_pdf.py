from __future__ import annotations
import base64
import sys
import tempfile
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from logging import Logger
from pathlib import Path
from pyhanko.pdf_utils.generic import (
    ArrayObject as PhArrayObject,
    DictionaryObject as PhDictionaryObject,
    IndirectObject as PhIndirectObject,
    NameObject as PhNameObject
)
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.signers import PdfSigner, SimpleSigner, PdfSignatureMetadata
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.stamp import TextStampStyle
from pyhanko.sign.timestamps import HTTPTimeStamper
from PyPDF2 import PdfReader
from PyPDF2.generic import ArrayObject, ByteStringObject, DictionaryObject, Field
from pypomes_core import TZ_LOCAL, file_get_data, exc_format
from requests.auth import HTTPBasicAuth
from typing import Any, Literal

from .crypto_common import (
    HashAlgorithm, _cms_build_cert_chain,
    _cms_verify_payload_hash, _cms_get_attr_value, _cms_get_tsa_info,
    _crypto_get_signature_padding, _crypto_verify_signature
)


class CryptoPdf:
    """
    Python code to extract crypto data from a *PAdES* compliant, digitally signed, PDF file.

    The crypto data is mostly in *Cryptographic Message Syntax* (CMS), a standard for digitally signing,
    digesting, authenticating, and encrypting arbitrary message content. In the case of the *PAdES* standard,
    some deviations exist, due to the utilization of PDF dictionaries to hold some of the data.

    These are the instance variables:
        - signatures: list of *SignatureInfo*, holds the crypto data of the document's signatures
        - pdf_bytes: holds the full bytes content of the PDF file, on which the payload ranges are applied
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
                 doc_in: BytesIO | Path | str | bytes,
                 doc_pwd: str = None,
                 errors: list[str] = None) -> None:
        """
        Instantiate the *CryptoPdf* class, and extract the relevant crypto data.

        The nature of *doc_in* depends on its data type:
          - type *BytesIO*: *doc_in* is a byte stream
          - type *Path*: *doc_in* is a path to a file holding the data
          - type *bytes*: *doc_in* holds the data (used as is)
          - type *str*: *doc_in* holds the data (used as utf8-encoded)

        If *doc_in* is encrypted, the decryption password must be provided in *doc_pwd*.

        :param doc_in: a digitally signed, *PAdES* conformant, PDF file
        :param doc_pwd: optional password for file decryption
        :param errors: incidental errors (may be non-empty)
        """
        # declare/initialize the instance variables
        self.signatures: list[CryptoPdf.SignatureInfo] = []
        self.pdf_bytes: bytes

        # retrieve the PDF data
        self.pdf_bytes = file_get_data(file_data=doc_in)

        # define a local errors list
        curr_errors: list[str] = []

        pdf_stream: BytesIO = BytesIO(initial_bytes=self.pdf_bytes)
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
            payload_range: tuple[int, int, int, int] = (int(from_1), int(len_1), int(from_2), int(len_2))
            payload: bytes = self.pdf_bytes[from_1:from_1+len_1] + self.pdf_bytes[from_2:from_2+len_2]

            # extract signature data (CMS structure)
            sig_obj: ByteStringObject = contents.get_object()
            cms_obj: cms.ContentInfo = cms.ContentInfo.load(encoded_data=sig_obj)
            signed_data: cms.SignedData = cms_obj["content"]
            signer_info: cms.SignerInfo = signed_data["signer_infos"][0]
            signed_attrs: cms.CMSAttributes = signer_info["signed_attrs"]
            hash_algorithm: HashAlgorithm = HashAlgorithm(signer_info["digest_algorithm"]["algorithm"].native)
            signature: bytes = signer_info["signature"].native
            signature_algorithm: str = signer_info["signature_algorithm"]["algorithm"].native
            signature_timestamp: datetime = _cms_get_attr_value(cms_attrs=signed_attrs,
                                                                attr_type="signing_time")
            # extract and validate the payload hash
            computed_hash: bytes = _cms_verify_payload_hash(signed_attrs=signed_attrs,
                                                            payload=payload,
                                                            hash_alg=hash_algorithm,
                                                            errors=curr_errors,
                                                            logger=CryptoPdf.logger)
            if curr_errors:
                break

            # extract the certificate chain and the signer's certificate proper
            cert_data: tuple[list[bytes], int] = _cms_build_cert_chain(signed_data=signed_data,
                                                                       signer_info=signer_info)
            cert_chain: list[bytes] = cert_data[0]
            cert_ord: int = cert_data[1]
            signer_cert: x509.Certificate = x509.load_der_x509_certificate(data=cert_chain[cert_ord])
            public_key: PublicKeyTypes = signer_cert.public_key()
            cert_sn: int = signer_cert.serial_number
            signature_padding: padding.AsymmetricPadding = \
                _crypto_get_signature_padding(public_key=public_key,
                                              signature_alg=signature_algorithm,
                                              hash_alg=hash_algorithm)
            # identify signer
            subject: x509.name.Name = signer_cert.subject
            signer_cn: str = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

            # TSA timestamp info (optional)
            tsa_data: tuple[datetime, str, str] = _cms_get_tsa_info(signer_info=signer_info,
                                                                    logger=CryptoPdf.logger)
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
                                     logger=CryptoPdf.logger)
            if curr_errors:
                break

            # build the signature's crypto data and save it
            sig_info: CryptoPdf.SignatureInfo = CryptoPdf.SignatureInfo(
                payload_range=payload_range,
                payload_hash=computed_hash,
                hash_algorithm=hash_algorithm,
                signature=signature,
                signature_algorithm=signature_algorithm,
                signature_timestamp=signature_timestamp,
                public_key=public_key,
                signer_cn=signer_cn,
                signer_cert=signer_cert,
                cert_sn=cert_sn,
                cert_chain=cert_chain,
                tsa_timestamp=tsa_timestamp,
                tsa_policy=tsa_policy,
                tsa_sn=tsa_sn
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

    def get_cert_chain(self,
                       sig_seq: int = 0) -> list[bytes]:
        """
        Retrieve the certificate chain associated with a reference signature, as specified in *sig_seq*.

        The natural ordering of the signatures in a *PAdES* compliant, digitally signed, PDF file is the
        chronological *latest-first* order. The value of *sig_seq* is subtracted from the ordinal position
        of the last signature in the signatures list, to yield the ordinal position of the reference signature.
        It defaults to *0*, indicating the latest signature. If the operation yields a number out of the range
        of available signatures, the latest signature is selected.

        :param sig_seq: the relative ordinal position of the reference signature
        :return: the signature, as per *fmt* (Base64-encoded or raw bytes)
        """
        sig_info: CryptoPdf.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
        return sig_info.cert_chain

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
        # declare the return variable
        result: dict[str, Any]

        sig_info: CryptoPdf.SignatureInfo = self.__get_sig_info(sig_seq=sig_seq)
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
        sig_ordinal: int = max(-1, len(self.signatures) - sig_seq - 1)
        return self.signatures[sig_ordinal]

    @staticmethod
    def set_logger(logger: Logger) -> None:
        """
        Configure the logger to be used in this module's operations.

        :param logger: the operations logger
        """
        CryptoPdf.logger = logger

    @staticmethod
    def sign(doc_in: BytesIO | Path | str | bytes,
             pfx_in: BytesIO | Path | str | bytes,
             pfx_pwd: str | bytes = None,
             doc_out: BytesIO | Path | str = None,
             location: str = None,
             reason: str = None,
             make_visible: bool = False,
             page_num: int = 0,
             box: tuple[int, int, int, int] = (50, 50, 250, 150),
             tsa_url: str = None,
             tsa_username: str = None,
             tsa_password: str = None,
             errors: list[str] = None) -> CryptoPdf | None:
        """
        Digitally sign a PDF file in *PAdES* format, using an A1 certificate.

        The natures of *doc_in* and *pfx_in* depend on their respective data types:
          - type *BytesIO*: is a byte stream
          - type *Path*: is a path to a file holding the data
          - type *bytes*: holds the data (used as is)
          - type *str*: holds the data (used as utf8-encoded)

        Supports visible signature appearance, TSA timestamping, and multiple signatures.
        If specified, *doc_out* must be a *BytesIO* object, or contain a valid filepath. If the latter is
        provided without a file extension, it is set to *.pdf*. If the file already exists, it will be overwritten.

        :param doc_in: input PDF data
        :param pfx_in: the PKCS#12 (*.pfx*) data, containing A1 certificate and private key
        :param pfx_pwd: password for the *.pfx* data (if not provided, *pfx_in* is assumed to be unencrypted)
        :param doc_out: byte stream or path to output the signed PDF file (optional, no output if not provided)
        :param location: location of signing
        :param reason: reason for signing
        :param make_visible: whether to include a visible signature appearance
        :param page_num: page number for the visible signature (0-based, specify -1 for last page)
        :param box: (x1, y1, x2, y2) coordinates for the signature box
        :param tsa_url: TSA server URL for timestamping
        :param tsa_username: TSA username (if required)
        :param tsa_password: TSA password (if required)
        :param errors: incidental errors (may be non-empty)
        :return: the corresponding instance of *CryptoPdf*, or *None* if error
        """
        # initialize the return variable
        result: CryptoPdf | None = None

        # instantiate the PyHanko's signer
        is_temp: bool = False
        pwd_bytes = pfx_pwd.encode() if isinstance(pfx_pwd, str) else pfx_pwd
        # PyHanko's SimpleSigner requires a path to a file
        if not isinstance(pfx_in, Path):
            pfx_bytes: bytes = file_get_data(file_data=pfx_in)
            is_temp = True
            with tempfile.NamedTemporaryFile(mode="wb",
                                             delete=False) as tmp:
                tmp.write(pfx_bytes)
                pfx_in = Path(tmp.name)
        # returns 'None' on failure
        simple_signer: SimpleSigner = SimpleSigner.load_pkcs12(pfx_file=pfx_in,
                                                               passphrase=pwd_bytes)
        if is_temp:
            pfx_in.unlink(missing_ok=True)

        if simple_signer:
            # configure stamp style
            stamp_style: TextStampStyle | None = None
            if make_visible:
                stamp_text: str = f"Signed by {simple_signer.subject_name}"
                if reason:
                    stamp_text += f"\nReason: {reason}"
                if location:
                    stamp_text += f"\nLocation: {location}"
                stamp_text += f"\nDate: {datetime.now(tz=TZ_LOCAL)}"
                stamp_style = TextStampStyle(stamp_text=stamp_text)

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

            # open PDF file for incremental signing
            doc_in = file_get_data(file_data=doc_in)
            pdf_stream: BytesIO = BytesIO(initial_bytes=doc_in)

            pdf_stream.seek(0)
            writer: IncrementalPdfFileWriter = IncrementalPdfFileWriter(input_stream=pdf_stream,
                                                                        strict=False)
            # Use PdfFileReader to inspect fields
            reader: PdfFileReader = PdfFileReader(stream=pdf_stream)
            acroform_ref: PhIndirectObject = reader.root.get("/AcroForm")
            sig_field: str | None = None
            field_count: int = 0

            if acroform_ref:
                # dereference IndirectObject
                acroform: PhDictionaryObject = acroform_ref.get_object()
                fields_array: PhArrayObject = acroform.get("/Fields") or []
                for field_ref in fields_array:
                    field_obj: PhDictionaryObject = field_ref.get_object()
                    field_type: PhNameObject = field_obj.get("/FT")
                    if field_type == "/Sig":
                        field_count += 1
                        field_value: PhIndirectObject = field_obj.get("/V")
                        if sig_field is None and field_value is None:
                            # use existing unused field
                            sig_field = field_obj.get("/T")
            if sig_field:
                # no need to create a new field
                new_field_spec = None
            else:
                # obtain the last page index
                if page_num == -1:
                    save_pos: int = pdf_stream.tell()
                    pdf_stream.seek(0)
                    temp_reader: PdfReader = PdfReader(stream=pdf_stream)
                    page_num = len(temp_reader.pages) - 1
                    del temp_reader
                    pdf_stream.seek(save_pos)
                # create a new field
                sig_field = f"Signature{field_count + 1}"
                new_field_spec = SigFieldSpec(sig_field_name=sig_field,
                                              box=box,
                                              on_page=page_num)
            # create signature metadata
            sig_metadata: PdfSignatureMetadata = PdfSignatureMetadata(field_name=sig_field,
                                                                      reason=reason,
                                                                      location=location)
            # create PdfSigner
            pdf_signer: PdfSigner = PdfSigner(signature_meta=sig_metadata,
                                              signer=simple_signer,
                                              timestamper=timestamper,
                                              stamp_style=stamp_style,
                                              new_field_spec=new_field_spec)
            output_buf: BytesIO | None = None
            try:
                output_buf = pdf_signer.sign_pdf(pdf_out=writer)
            except Exception as e:
                exc_err: str = exc_format(exc=e,
                                          exc_info=sys.exc_info())
                if CryptoPdf.logger:
                    CryptoPdf.logger.error(msg=exc_err)
                if isinstance(errors, list):
                    errors.append(exc_err)

            if output_buf:
                crypto_pdf: CryptoPdf = CryptoPdf(doc_in=output_buf,
                                                  errors=errors)
                if not errors:
                    result = crypto_pdf

                    # output the signed/re-signed PDF file
                    if doc_out:
                        output_buf.seek(0)
                        signed_pdf: bytes = output_buf.read()
                        if isinstance(doc_out, str):
                            doc_out = Path(doc_out)
                        if isinstance(doc_out, Path):
                            if not doc_out.suffix:
                                doc_out = doc_out.with_suffix(".pdf")
                            # write the signed PDF file
                            with doc_out.open("wb") as out_f:
                                out_f.write(signed_pdf)
                        elif isinstance(doc_out, BytesIO):
                            # stream the signed PDF file
                            doc_out.write(signed_pdf)
        else:
            msg: str = "Unable to load PKCS#12 data from 'pfx_data'"
            if CryptoPdf.logger:
                CryptoPdf.logger.error(msg=msg)
            if isinstance(errors, list):
                errors.append(msg)

        return result
