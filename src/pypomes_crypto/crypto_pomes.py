import sys
from asn1crypto.x509 import Certificate
from Crypto.Hash import SHA256
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey.RSA import import_key, RsaKey
from Crypto.Signature import pkcs1_15
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from io import BytesIO
from pathlib import Path
from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature
from pyhanko_certvalidator import ValidationContext
from pyhanko.keys import load_certs_from_pemder, load_certs_from_pemder_data
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.status import PdfSignatureStatus
from pypomes_core import exc_format
from typing import BinaryIO

from .crypto_pkcs7 import CryptoPkcs7


def crypto_validate_p7s(errors: list[str], p7s_file: str | bytes, p7s_payload: str | bytes = None) -> bool:
    """
    Validate the digital signature of a PKCS#7 file.

    If a *list* is provided in *errors*, the following inconsistencies are reported:
        - The digital signature is invalid
        - Error from CryptoPkcs7 instantiation

    :param errors: incidental error messages
    :param p7s_file: a p7s file path, or the bytes thereof
    :param p7s_payload: a payload file path, or the bytes thereof
    :return: True if the input data are consistent, False otherwise
    """
    # instantiate the return variable
    result: bool = True

    # instantiate the PKCS7 object
    pkcs7: CryptoPkcs7
    try:
        pkcs7 = CryptoPkcs7(p7s_file, p7s_payload)
    except Exception as e:
        result = False
        if isinstance(errors, list):
            errors.append(exc_format(e, sys.exc_info()))

    # any error ?
    if result:
        # no, verify the signature
        try:
            # noinspection PyUnboundLocalVariable
            rsa_key: RsaKey = import_key(pkcs7.public_key)
            sig_scheme: PKCS115_SigScheme = pkcs1_15.new(rsa_key)
            # TODO: build 'sha256_hash' directly from 'pkcs7.payload_hash'
            sha256_hash: SHA256Hash = SHA256.new(data=pkcs7.payload)
            # TODO: fix the verification process
            sig_scheme.verify(sha256_hash, pkcs7.signature)
        except ValueError:
            result = False
            if isinstance(errors, list):
                errors.append("The digital signature is invalid")
        except Exception as e:
            if isinstance(errors, list):
                errors.append(exc_format(e, sys.exc_info()))

    return result


def crypto_validate_pdf(errors: list[str],
                        pdf_file: str | bytes, certs_file:  str | bytes = None) -> bool:
    """
    Validate the digital signature of a PDF file.

    If a *list* is provided in *errors*, the following inconsistencies are reported:
        - The file is not digitally signed
        - The digital signature is not valid
        - The certificate used has been revoked
        - The certificate used is not trusted
        - The signature block is not intact
        - A bad seed value found

    :param errors: incidental error messages
    :param pdf_file: a PDF file path, or the PDF file bytes
    :param certs_file: a path to a file containing a PEM/DER-encoded certificate chain, or the bytes thereof
    :return: True if the input data are consistent, False otherwise
    """
    # initialize the return variable
    result: bool = True

    # obtain the PDF data
    if isinstance(pdf_file, bytes):
        # argument is type 'bytes'
        wrapper: BinaryIO = BytesIO(pdf_file)
    else:  # isinstance(pdf_file, str)
        # argumento is a file path
        wrapper: BinaryIO = Path.open(Path(pdf_file), "rb")
    pdf_reader: PdfFileReader = PdfFileReader(wrapper)

    # obtain the validation context
    cert: Certificate | None = None
    if isinstance(certs_file, bytes):
        # argument is type 'bytes'
        cert = load_certs_from_pemder_data(certs_file)
    elif isinstance(certs_file, str):
        # argumento is a file path
        cert = load_certs_from_pemder(certs_file)
    validation_context = ValidationContext(cert)  # 'cert' might be None

    # obtain the list of digital signatures
    signatures: list[EmbeddedPdfSignature] = pdf_reader.embedded_signatures

    # were signatures retrieved ?
    if signatures:
        # yes, verify them
        for signature in signatures:
            error: str | None = None
            status: PdfSignatureStatus = validate_pdf_signature(signature, validation_context)
            if status.revoked:
                error = "The certificate used has been revoked"
            elif not status.intact:
                error = "The signature block is not intact"
            elif not status.trusted and cert:
                error = "The certificate used is not trusted"
            elif not status.seed_value_ok:
                error = "A bad seed value found"
            elif not status.valid:
                error = "The digital signature is not valid"

            # has an error been flagged ?
            if error:
                # yes, report it
                result = False
                errors.append(error)
    else:
        # no, report the problem
        result = False
        errors.append("The file is not digitally signed")

    return result
