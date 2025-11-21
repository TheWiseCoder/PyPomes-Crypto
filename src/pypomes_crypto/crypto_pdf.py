from __future__ import annotations
import base64
import json
from asn1crypto import cms, tsp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from dataclasses import dataclass
from datetime import datetime
from io import StringIO
from logging import Logger
from pathlib import Path
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.signers import sign_pdf, PdfSigner, SimpleSigner, PdfSignatureMetadata
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.stamp import TextStampStyle
from pyhanko.sign.timestamps import HTTPTimeStamper
from PyPDF2 import PdfReader
from pypomes_core import TZ_LOCAL, file_get_data
from requests.auth import HTTPBasicAuth
from typing import Any, Literal

from .crypto_common import HashAlgorithm, _cryptography_hash


class CryptoPdf:
    """
    Python code to extract crypto data from a *PAdES* compliant, digitally signed, PDF file.

    This is the only instance variable, used to hold the crypto data of the document's signatures :
    - signatures: list of *SignatureInfo*
    """
    logger: Logger | None = None

    @dataclass(frozen=True)
    class SignatureInfo:
        """
        These are the attributes holding the signature data.
        """
        payload: bytes
        payload_hash: bytes
        hash_algorithm: HashAlgorithm
        signature: bytes
        signature_algorithm: str
        signature_timestamp: datetime
        public_key: RSAPublicKey
        cert_chain: list[bytes]
        signer_common_name: str
        issuer: str
        signer_cert: x509.Certificate
        tsa_timestamp: datetime
        tsa_policy: str
        tsa_serial_number: str
        tsa_cert_fingerprint_sha256: str

    def __init__(self,
                 pdf_data: str,
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
        :param errors: incidental errors
        """
        # initialize the structure holding the crypto data
        self.signatures: list[CryptoPdf.SignatureInfo] = []

        # retrieve the PDF data
        pdf_bytes: bytes = file_get_data(file_data=pdf_data)
        pdf_stream: StringIO = StringIO(initial_value=pdf_bytes.decode(encoding="utf-8"))
        pdf_stream.seek(0)

        # retrieve the signature fields
        reader: PdfReader = PdfReader(stream=pdf_stream,
                                      password=pdf_pwd)
        sig_fields = [field for field in reader.get_fields().values()
                      if field.get("/FT") == "/Sig"] or []

        # process the signature fields
        for sig_field in sig_fields:
            sig_dict: dict[str, Any] = sig_field.get("/V")
            byte_range: list[int] = sig_dict["/ByteRange"]
            contents = sig_dict["/Contents"]

            # extract payload
            payload: bytes = (pdf_bytes[byte_range[0]:byte_range[1]] +
                              pdf_bytes[byte_range[2]:byte_range[3]])

            # extract signature data (CMS structure)
            signature = contents.get_object()
            cms_obj: cms.ContentInfo = cms.ContentInfo.load(encoded_data=signature)
            signed_data: cms.SignedData = cms_obj["content"]
            signer_info = signed_data["signer_infos"][0]

            # extract signature algorithm
            signature_algorithm: str = signer_info["signature_algorithm"]["algorithm"].native

            # extract signature timestamp and payload hash
            payload_hash: bytes | None = None
            signature_timestamp: datetime | None = None
            if "signed_attrs" in signer_info:
                for attr in signer_info["signed_attrs"]:
                    match attr["type"].native:
                        case "message_digest":
                            payload_hash = attr["values"][0].native
                        case "signing_time":
                            signature_timestamp = attr["values"][0].native
            # validate hash
            from .crypto_pomes import crypto_hash
            digest_alg: str = signed_data["digest_algorithms"][0]["algorithm"].native
            true_hash: bytes = crypto_hash(msg=payload,
                                           alg=HashAlgorithm(digest_alg))
            if not payload_hash:
                payload_hash = true_hash
            elif payload_hash != true_hash:
                msg: str = f"Invalid digest for signature timestamp '{signature_timestamp}'"
                if CryptoPdf.logger:
                    CryptoPdf.logger.error(msg=msg)
                if isinstance(errors, list):
                    errors.append(msg)
                    break

            # extract certificates and public key
            cert_chain: list[bytes] = []
            certs = signed_data["certificates"]
            for cert in certs:
                der_bytes: bytes = cert.dump()
                cert_chain.append(der_bytes)
            signer_cert = x509.load_der_x509_certificate(data=cert_chain[0],
                                                         backend=default_backend())
            public_key: RSAPublicKey = signer_cert.public_key()

            # Extract signer identity
            subject = signer_cert.subject
            issuer = signer_cert.issuer
            signer_common_name: str = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            issuer_name: str = issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

            # TSA timestamp info (optional)
            tsa_timestamp: datetime | None = None
            tsa_policy: str | None = None
            tsa_serial_number: str | None = None
            tsa_cert_fingerprint_sha256: str | None = None

            for attr in signer_info.get("unsigned_attrs") or []:
                if attr["type"].native == "signature_time_stamp_token":
                    # Load the timestamp token as CMS ContentInfo
                    tsp_token = cms.ContentInfo.load(attr["values"][0].contents)

                    # extract SignedData from the token
                    signed_data: cms.SignedData = tsp_token["content"]

                    # extract TSTInfo from 'encap_content_info'
                    encoded_data = signed_data["encap_content_info"]["content"].native
                    tst_info = tsp.TSTInfo.load(encoded_data=encoded_data)

                    # extract TSA timestamp details
                    tsa_timestamp = tst_info["gen_time"].native
                    tsa_policy = tst_info["policy"].native
                    tsa_serial_number = hex(tst_info["serial_number"].native)

                    # calculate the TSA certificate fingerprint
                    tsa_cert = signed_data["certificates"][0]
                    tsa_cert_bytes = tsa_cert.dump()
                    tsa_cert_obj = x509.load_der_x509_certificate(data=tsa_cert_bytes,
                                                                  backend=default_backend())
                    tsa_cert_fingerprint_sha256: str = tsa_cert_obj.fingerprint(hashes.SHA256()).hex()
                    break

            # verify the signature
            try:
                public_key.verify(signature=signature,
                                  data=payload_hash,
                                  padding=padding.PKCS1v15(),
                                  algorithm=_cryptography_hash(digest_alg))
            except Exception:
                msg = f"Signature of '{signer_common_name}' is not valid"
                if CryptoPdf.logger:
                    CryptoPdf.logger.error(msg=msg)
                if isinstance(errors, list):
                    errors.append(msg)
                    break

            # build the signature's crypto data and save it
            sig_info: CryptoPdf.SignatureInfo = CryptoPdf.SignatureInfo(
                payload=payload,
                payload_hash=payload_hash,
                hash_algorithm=HashAlgorithm(digest_alg),
                signature=signature,
                signature_algorithm=signature_algorithm,
                signature_timestamp=signature_timestamp,
                public_key=public_key,
                cert_chain=cert_chain,
                signer_common_name=signer_common_name,
                issuer=issuer_name,
                signer_cert=signer_cert,
                tsa_timestamp=tsa_timestamp,
                tsa_policy=tsa_policy,
                tsa_serial_number=tsa_serial_number,
                tsa_cert_fingerprint_sha256=tsa_cert_fingerprint_sha256
            )
            self.signatures.append(sig_info)

        if not errors and not self.signatures:
            msg: str = "No digital signatures found in PDF file"
            if CryptoPdf.logger:
                CryptoPdf.logger.error(msg=msg)
            if isinstance(errors, list):
                errors.append(msg)

    def get_digest(self,
                   fmt: Literal["base64", "bytes"],
                   sig_seq: int = 0) -> str | bytes:
        """
        Retrieve the digest associated with a reference signature, as specified in *sig_seq* and *fmt*.

        The natural ordering of the signatures in a *PAdES* compliant, digitally signed, PDF file is *last-to-first*.
        The value of *sig_seq* is subtracted from the ordinal position of the last signature in the signatures list,
        to yield the ordinal position of the reference signature. It defaults to *0*, indicating the latest signature.
        If the operation yields a number out of the range of available signatures, the latest signature is selected.

        :param fmt: the format to use
        :param sig_seq: the relative ordinal position of the reference signature
        :return: the digest, as per *fmt* (Base64-encoded or raw bytes)
        """
        sig_ordinal = max(0, len(self.signatures) - sig_seq - 1)
        sig_info: CryptoPdf.SignatureInfo = self.signatures[sig_ordinal]
        return sig_info.payload_hash \
            if fmt == "bytes" else base64.b64encode(s=sig_info.payload_hash).decode(encoding="utf-8")

    def get_signature(self,
                      fmt: Literal["base64", "bytes"],
                      sig_seq: int = 0) -> str | bytes:
        """
        Retrieve the signature associated with a reference signature, as specified in *sig_seq* and *fmt*.

        The natural ordering of the signatures in a *PAdES* compliant, digitally signed, PDF file is *last-to-first*.
        The value of *sig_seq* is subtracted from the ordinal position of the last signature in the signatures list,
        to yield the ordinal position of the reference signature. It defaults to *0*, indicating the latest signature.
        If the operation yields a number out of the range of available signatures, the latest signature is selected.

        :param fmt: the format to use
        :param sig_seq: the relative ordinal position of the reference signature
        :return: the signature, as per *fmt* (Base64-encoded or raw bytes)
        """
        sig_ordinal = max(0, len(self.signatures) - sig_seq - 1)
        sig_info: CryptoPdf.SignatureInfo = self.signatures[sig_ordinal]
        return sig_info.signature \
            if fmt == "bytes" else base64.b64encode(s=sig_info.signature).decode(encoding="utf-8")

    def get_public_key(self,
                       fmt: Literal["base64", "der", "pem"],
                       sig_seq: int = 0) -> str | bytes:
        """
        Retrieve the public key associated with a reference signature, as specified in *sig_seq* and *fmt*.

        The natural ordering of the signatures in a *PAdES* compliant, digitally signed, PDF file is *last-to-first*.
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

        sig_ordinal = max(0, len(self.signatures) - sig_seq - 1)
        sig_info: CryptoPdf.SignatureInfo = self.signatures[sig_ordinal]

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

    def export_metadata(self) -> str:
        """
        Export the certificate chain metadata as a JSON-encoded, formatted, string.

        :return: the certificate chain metadata as a JSON-encoded, formatted, string
        """
        export_list = []
        for idx, sig in enumerate(self.signatures, start=1):
            cert = sig.signer_cert
            signer_fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()

            # compute fingerprints for the entire chain
            chain_fingerprints = []
            for cert_bytes in sig.cert_chain:
                chain_cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
                chain_fingerprints.append(chain_cert.fingerprint(hashes.SHA256()).hex())

            sig_metadata = {
                "signature_index": idx,
                "signer_common_name": sig.signer_common_name,
                "issuer": sig.issuer,
                "hash_algorithm": sig.hash_algorithm,
                "signature_algorithm": sig.signature_algorithm,
                "signature_timestamp": sig.signature_timestamp.isoformat() if sig.signature_timestamp else None,
                "cert_serial_number": hex(cert.serial_number),
                "cert_not_before": cert.not_valid_before.isoformat(),
                "cert_not_after": cert.not_valid_after.isoformat(),
                "cert_subject": cert.subject.rfc4514_string(),
                "cert_issuer": cert.issuer.rfc4514_string(),
                "cert_chain_length": len(sig.cert_chain),
                "signer_cert_fingerprint_sha256": signer_fingerprint_sha256,
                "cert_chain_fingerprints_sha256": chain_fingerprints,
                # TSA details
            }
            if sig.tsa_cert_fingerprint_sha256:
                sig_metadata.update({
                    "tsa_timestamp": sig.tsa_timestamp.isoformat()
                    if sig.tsa_timestamp else None,
                    "tsa_policy": sig.tsa_policy,
                    "tsa_serial_number": sig.tsa_serial_number,
                    "tsa_cert_fingerprint_sha256": sig.tsa_cert_fingerprint_sha256
                })

            export_list.append(sig_metadata)

        return json.dumps(obj=export_list,
                          indent=2)

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
        :param pdf_out: path to the output signed PDF file (optinal, no output if not provided)
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
            with pdf_out.open("wb") as out_f:
                out_f.write(signed_pdf)

        return CryptoPdf(pdf_data=signed_pdf)
