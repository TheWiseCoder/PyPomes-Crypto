import hashlib
import pickle
import sys
from asn1crypto.x509 import Certificate
from collections.abc import Iterable
from contextlib import suppress
from Crypto.Hash import SHA256
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey.RSA import import_key, RsaKey
from Crypto.Signature import pkcs1_15
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from io import BytesIO
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature
from pyhanko_certvalidator import ValidationContext
from pyhanko.keys import load_certs_from_pemder_data
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.status import PdfSignatureStatus
from pypomes_core import file_get_data, exc_format, env_get_str, APP_PREFIX
from typing import Any, Final

from .crypto_pkcs7 import CryptoPkcs7

CRYPTO_DEFAULT_HASH_ALGORITHM: Final[str] = \
    env_get_str(key=f"{APP_PREFIX}_CRYPTO_DEFAULT_HASH_ALGORITHM",
                def_value="sha256")


def crypto_validate_p7s(errors: list[str],
                        p7s_file: Path | str | bytes,
                        p7s_payload: str | bytes = None) -> bool:
    """
    Validate the digital signature of a PKCS#7 file.

    If a *list* is provided in *errors*, the following inconsistencies are reported:
        - The digital signature is invalid
        - Error from CryptoPkcs7 instantiation

    :param errors: incidental error messages
    :param p7s_file: a p7s file path, or the bytes thereof
    :param p7s_payload: a payload file path, or the bytes thereof
    :return: 'True' if the input data are consistent, 'False' otherwise
    """
    # instantiate the return variable
    result: bool = False

    # instantiate the PKCS7 object
    pkcs7: CryptoPkcs7 | None = None
    try:
        pkcs7 = CryptoPkcs7(p7s_file=p7s_file,
                            p7s_payload=p7s_payload)
    except Exception as e:
        if isinstance(errors, list):
            errors.append(exc_format(exc=e,
                                     exc_info=sys.exc_info()))

    # was the PKCS7 object instanciated ?
    if pkcs7:
        # yes, verify the signature
        try:
            # noinspection PyUnboundLocalVariable
            rsa_key: RsaKey = import_key(extern_key=pkcs7.public_bytes)
            sig_scheme: PKCS115_SigScheme = pkcs1_15.new(rsa_key=rsa_key)
            sha256_hash: SHA256Hash = SHA256.new(data=pkcs7.payload)
            # TODO @gtnunes: fix the verification process
            sig_scheme.verify(msg_hash=sha256_hash,
                              signature=pkcs7.signature)
            result = True
        except ValueError:
            if isinstance(errors, list):
                errors.append("The digital signature is invalid")
        except Exception as e:
            if isinstance(errors, list):
                errors.append(exc_format(exc=e,
                                         exc_info=sys.exc_info()))
    return result


def crypto_validate_pdf(errors: list[str] | None,
                        pdf_file: Path | str | bytes,
                        certs_file: Path | str | bytes = None) -> bool:
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
    :return: 'True' if the input data are consistent, 'False' otherwise
    """
    # initialize the return variable
    result: bool = True

    # obtain the PDF reader
    pdf_bytes: bytes = file_get_data(file_data=pdf_file)
    pdf_reader: PdfFileReader = PdfFileReader(stream=BytesIO(initial_bytes=pdf_bytes))

    # obtain the validation context
    certs: Iterable[Certificate] | None = None
    if certs_file:
        certs_bytes: bytes = file_get_data(file_data=certs_file)
        if certs_bytes:
            certs = load_certs_from_pemder_data(cert_data_bytes=certs_bytes)
    validation_context: ValidationContext = ValidationContext(trust_roots=certs)

    # obtain the list of digital signatures
    signatures: list[EmbeddedPdfSignature] = pdf_reader.embedded_signatures

    # were signatures retrieved ?
    if signatures:
        # yes, traverse the list verifying them
        for signature in signatures:
            error: str | None = None
            status: PdfSignatureStatus = validate_pdf_signature(embedded_sig=signature,
                                                                signer_validation_context=validation_context)
            if status.revoked:
                error = "The certificate used has been revoked"
            elif not status.intact:
                error = "The signature block is not intact"
            elif not status.trusted and certs:
                error = "The certificate used is not trusted"
            elif not status.seed_value_ok:
                error = "A bad seed value found"
            elif not status.valid:
                error = "The digital signature is not valid"

            # has an error been flagged ?
            if error:
                # yes, report it
                if isinstance(errors, list):
                    errors.append(error)
                result = False
    else:
        # no, report the problem
        if isinstance(errors, list):
            errors.append("The file is not digitally signed")
        result = False

    return result


def crypto_compute_hash(msg: Path | str | bytes | Any,
                        alg: str = CRYPTO_DEFAULT_HASH_ALGORITHM) -> bytes:
    """
    Compute the hash of *msg*, using the algorithm specified in *alg*.

    Supported algorithms: *md5*, *blake2b*, *blake2s*, *sha1*, *sha224*, *sha256*, *sha384*,
    *sha512*, *sha3_224*, *sha3_256*, *sha3_384*, *sha3_512*, *shake_128*, *shake_256*.

    :param msg: the message to calculate the hash for, or a path to a file
    :param alg: the algorithm to use (defaults to an environment-defined value, or to 'sha256')
    :return: the hash value obtained, or 'None' if the hash could not be computed
    """
    # initialize the return variable
    result: bytes | None = None

    # instantiate the hasher
    hasher = hashlib.new(name=alg.lower())

    # what is the type of the message ?
    if isinstance(msg, bytes):
        # argument is type 'bytes'
        hasher.update(msg)
        result = hasher.digest()

    elif isinstance(msg, Path | str):
        # argument is a file path
        buf_size: int = 128 * 1024
        file_path: Path = Path(msg)
        with file_path.open(mode="rb") as f:
            file_bytes: bytes = f.read(buf_size)
            while file_bytes:
                hasher.update(file_bytes)
                file_bytes = f.read(buf_size)
        result = hasher.digest()

    else:
        # argument is unknown
        with suppress(Exception):
            data: bytes = pickle.dumps(obj=msg)
            if data:
                hasher.update(data)
                result = hasher.digest()

    return result


def crypto_generate_rsa_keys(key_size: int = 2048) -> (str, str):
    """
    Generate and return a matching pair of *RSA* private and public keys.

    The keys are serialized and *UTF-8* decoded to *str*.

    :param key_size: the key size (defaults to 2048 bytes)
    :return: a matching pair (private_key, public_key) of serialized RSA keys
    """
    # generate the private key
    priv_key: RSAPrivateKey = rsa.generate_private_key(public_exponent=65537,
                                                       key_size=key_size)
    priv_serialized: bytes = priv_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.PKCS8,
                                                    encryption_algorithm=serialization.NoEncryption())
    # obtain the matching public key
    pub_key: RSAPublicKey = priv_key.public_key()
    pub_serialized: bytes = pub_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
    # serialize and return the keys
    return priv_serialized.decode(), pub_serialized.decode()
