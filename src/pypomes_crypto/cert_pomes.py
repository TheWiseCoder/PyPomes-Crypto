import sys
import certifi
import requests
from contextlib import suppress
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, NoEncryption, KeySerializationEncryption, Encoding, PrivateFormat
)
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response
from cryptography.x509.oid import NameOID
from datetime import UTC, datetime, timedelta
from logging import Logger
from pathlib import Path
from pypomes_core import exc_format
from typing import Any, Literal


def cert_make_certificate(common_name: str,
                          organization: str,
                          locality: str,
                          province: str,
                          country: str,
                          valid_from: datetime = None,
                          valid_for: int = 365,
                          fmt: Literal["der", "pem", "x509"] = "der") -> (tuple[str, str] |
                                                                          tuple[bytes, bytes] |
                                                                          tuple[x509.Certificate, RSAPrivateKey]):
    """
    Generate a self-signed x509 digital certificate/private key set.

    The return format of the certificate and private key is specified in *fmt*:
        - *der*: *Distinguished Encoding Rules*, binary as *bytes* (the default)
        - *pem*: *Privacy-Enhanced Mail*, text-based as *str*
        - *x509*: *cryptography*'s *Certificate* and *RSAPrivateKey* objects

    :param common_name: the certificates's common name, typically the holder's identification
    :param organization: the reference organization
    :param locality: the reference locality, typically the name of a city
    :param province: the reference province, typically the name of a state or province
    :param country: the two-letter *Country Code Top-Level Domain* (ccTLD)
    :param valid_from: the certificate's validation start (defaults to now)
    :param valid_for: the certificate's validation period, in days (defaults to one year)
    :param fmt: the output format to use for the certificate and private key (defaults to *der*)
    :return: a self-signed x509 digital certificate, along with the corresponding private key
    """
    # generate RSA private key
    private_key: RSAPrivateKey = rsa.generate_private_key(public_exponent=65537,
                                                          key_size=2048)
    # build 'subject' and 'ìssuer'
    # (they are the same for self-signed certificates)
    subject_issuer: x509.Name = x509.Name([x509.NameAttribute(oid=NameOID.COUNTRY_NAME,
                                                              value=country.upper()),
                                           x509.NameAttribute(oid=NameOID.STATE_OR_PROVINCE_NAME,
                                                              value=province),
                                           x509.NameAttribute(oid=NameOID.LOCALITY_NAME,
                                                              value=locality),
                                           x509.NameAttribute(oid=NameOID.ORGANIZATION_NAME,
                                                              value=organization),
                                           x509.NameAttribute(oid=NameOID.COMMON_NAME,
                                                              value=common_name)])
    # build the validity period
    if valid_from is None:
        valid_from = datetime.now(tz=UTC)
    valid_to: datetime = valid_from + timedelta(days=valid_for)

    # build the certificate
    certificate: x509.Certificate = (x509.CertificateBuilder()
                                         .subject_name(name=subject_issuer)
                                         .issuer_name(name=subject_issuer)
                                         .public_key(key=private_key.public_key())
                                         .serial_number(number=x509.random_serial_number())
                                         .not_valid_before(time=valid_from)
                                         .not_valid_after(time=valid_to)
                                         .add_extension(extval=x509.BasicConstraints(ca=True,
                                                                                     path_length=None),
                                                        critical=True)
                                         .sign(private_key=private_key,
                                               algorithm=hashes.SHA256()))
    # format the output
    result: tuple[str, str] | tuple[bytes, bytes] | tuple[x509.Certificate, RSAPrivateKey]
    if fmt == "der":
        result = (certificate.public_bytes(encoding=Encoding.DER),
                  private_key.private_bytes(encoding=Encoding.DER,
                                            format=PrivateFormat.TraditionalOpenSSL,
                                            encryption_algorithm=NoEncryption()))
    elif fmt == "pem":
        result = (certificate.public_bytes(encoding=Encoding.PEM).decode(encoding="utf-8"),
                  private_key.private_bytes(encoding=Encoding.PEM,
                                            format=PrivateFormat.TraditionalOpenSSL,
                                            encryption_algorithm=NoEncryption()).decode(encoding="utf-8"))
    else:
        result = (certificate, private_key)

    return result


def cert_make_pfx(common_name: str,
                  organization: str,
                  locality: str,
                  province: str,
                  country: str,
                  valid_from: datetime = None,
                  valid_for: int = 365,
                  pfx_filepath: Path | str = None,
                  pfx_password: str | bytes = None,
                  friendly_name: str | bytes = None,
                  cert_set: list[x509.Certificate] = None) -> bytes:
    """
    Generate a PFX (PKCS#12) file by way of a self-signed x509 digital certificate/private key set.

    If specified, *pfx_filepath* must contain a valid filepath. If provided without a file extension,
    the latter is set to *.pfx". If the file already exists, it will be overwritten.

    :param common_name: the certificates's common name, typically the holder's identification
    :param organization: the reference organization
    :param locality: the reference locality, typically the name of a city
    :param province: the reference province, typically the name of a state or province
    :param country: the two-letter *Country Code Top-Level Domain* (ccTLD)
    :param valid_from: the certificate's validation start (defaults to now)
    :param valid_for: the certificate's validation period, in days (defaults to one year)
    :param pfx_filepath: optional path to output the *.pfx* file (no file written, if not provided)
    :param pfx_password: optional password for the *.pfx* file (file not encrypted, if not provided)
    :param friendly_name: optional friendly name for the certificate in the *.pfx* file
    :param cert_set: optional set of certificates to include in the *.pfx* file
    :return: the *.pfx* file bytes
    """
    # obtain a self-signed certificate and its corresponding private key
    pkcs7_data: tuple[x509.Certificate, RSAPrivateKey] = cert_make_certificate(common_name=common_name,
                                                                               organization=organization,
                                                                               locality=locality,
                                                                               province=province,
                                                                               country=country,
                                                                               valid_from=valid_from,
                                                                               valid_for=valid_for,
                                                                               fmt="x509")
    certificate: x509.Certificate = pkcs7_data[0]
    private_key: RSAPrivateKey = pkcs7_data[1]

    # obtain and return the PKCS#12 structure
    return cert_build_pfx(certificate=certificate,
                          private_key=private_key,
                          pfx_filepath=pfx_filepath,
                          pfx_password=pfx_password,
                          friendly_name=friendly_name,
                          cert_set=cert_set)


def cert_build_pfx(certificate: x509.Certificate,
                   private_key: RSAPrivateKey,
                   pfx_filepath: Path | str = None,
                   pfx_password: str | bytes = None,
                   friendly_name: str | bytes = None,
                   cert_set: list[x509.Certificate] = None) -> bytes:
    """
    Build a PFX (PKCS#12) file from cryptography's *Certificate* and *RSAPrivateKey* objects.

    If specified, *pfx_filepath* must contain a valid filepath. If provided without a file extension,
    the latter is set to *.pfx". If the file already exists, it will be overwritten.

    :param certificate: the *cryptography.x509.Certificate* object
    :param private_key: the *cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey* object
    :param pfx_filepath: optional path to output the *.pfx* file (no file written, if not provided)
    :param pfx_password: optional password for the *.pfx* file (file not emcrypted, if not provided)
    :param friendly_name: optional friendly name for the certificate in the *.pfx* file
    :param cert_set: optional set of certificates to include in the *.pfx* file
    :return: The content of the *.pfx* file as bytes
    """
    if isinstance(friendly_name, str):
        friendly_name = friendly_name.encode(encoding="utf-8")
    encryption: KeySerializationEncryption
    if pfx_password is None:
        encryption = NoEncryption()
    else:
        if isinstance(pfx_password, str):
            pfx_password = pfx_password.encode(encoding="utf-8")
        encryption = BestAvailableEncryption(password=pfx_password)

    result: bytes = serialize_key_and_certificates(name=friendly_name,
                                                   key=private_key,
                                                   cert=certificate,
                                                   cas=cert_set,
                                                   encryption_algorithm=encryption)
    # write the PKCS#12 structure to a file
    if pfx_filepath:
        # make sure 'pfx_filepath' is a 'Path'
        pfx_filepath = Path(pfx_filepath)
        if not pfx_filepath.suffix:
            pfx_filepath = pfx_filepath.with_suffix(".pfx")
        # write the file
        with pfx_filepath.open("wb") as f:
            f.write(result)

    return result


def cert_bundle_certs(certs: list[str | bytes | x509.Certificate],
                      fmt: Literal["der", "pem"] = "der") -> str | bytes:
    """
    Bundle the certificates in *certs* into a single char string or byte string.

    The format of the individual input certificates can be:
        - *der*: *Distinguished Encoding Rules*, binary as *bytes* (the default)
        - *pem*: *Privacy-Enhanced Mail*, text-based as *str*
        - *x509*: *cryptography.x509.Certificate*, object as non-serialized binary

    *PEM* is a text format with delimiters (*-----BEGIN CERTIFICATE-----* and *-----END CERTIFICATE-----*),
    whereas *DER* is a binary format having no delimiters. When bundling multiple *DER* certificates into a
    single byte string, a way to delimit them for later unbundling is therefore needed. The approach used
    here is to prefix each certificate with a fixed-size header holding its length.

    The output format of the bundle is given by *fmt*:
        - *der*: *Distinguished Encoding Rules*, binary as *bytes* (the default)
        - *pem*: *Privacy-Enhanced Mail*, text-based as *str*

    :param certs: the certificates to bundle
    :param fmt: the output format to use for the individual certificates (defaults to *der*)
    :return: the bundle certificatrs as a char string or byte string
    """
    # initialize the return variable
    result: str | bytes = "" if fmt == "pem" else b""

    for cert in certs:
        cert_der: bytes | None = None
        cert_pem: str | None = None
        if isinstance(cert, x509.Certificate):
            # 'cert' is a certificate object
            if fmt == "der":
                cert_der: bytes = cert.public_bytes(encoding=Encoding.DER)
            else:
                cert_pem = cert.public_bytes(encoding=Encoding.PEM).decode(encoding="utf-8")
        elif isinstance(cert, str):
            # 'cert' is PEM-encoded
            if fmt == "der":
                cert_x509: x509.Certificate = x509.load_pem_x509_certificate(data=cert.encode(encoding="utf-8"))
                cert_der = cert_x509.public_bytes(encoding=Encoding.DER)
            else:
                cert_pem = cert
        elif isinstance(cert, bytes):
            # 'cert' is DER-encoded
            if fmt == "der":
                cert_der = cert
            else:
                cert_x509: x509.Certificate = x509.load_der_x509_certificate(data=cert)
                cert_pem = cert_x509.public_bytes(encoding=Encoding.PEM).decode(encoding="utf-8")

        if fmt == "der":
            result += len(cert_der).to_bytes(length=4,
                                             byteorder="big") + cert_der
        else:
            result += cert_pem

    return result


def cert_unbundle_certs(certs: str | bytes,
                        fmt: Literal["der", "pem", "x509"] = "der") -> list[str | bytes | x509.Certificate]:
    """
    Unbundle the certificates in *certs* into a list of certificates.

    The format of the individual input certificates in the bundle can be:
        - *der*: *Distinguished Encoding Rules*, binary as *bytes* (the default)
        - *pem*: *Privacy-Enhanced Mail*, text-based as *str*

    *PEM* is a text format with delimiters (*-----BEGIN CERTIFICATE-----* and *-----END CERTIFICATE-----*),
    whereas *DER* is a binary format having no delimiters. When bundling multiple *DER* certificates into a
    single byte string, a way to delimit them for later unbundling was therefore needed. The approach expected
    here is to have each certificate prefixed with a fixed-size header holding its length.

    The return format of the individual certificates is specified in *fmt*:
        - *der*: *Distinguished Encoding Rules*, binary as *bytes* (the default)
        - *pem*: *Privacy-Enhanced Mail*, text-based as *str*
        - *x509*: *cryptography.x509.Certificate*, object as non-serialized binary

    :param certs: the certificates to bundle
    :param fmt: the output format to use for the individual certificates (defaults to *der*)
    :return: the bundle certificatrs as a char string or byte string
    """
    # initialize the return variable
    result: list[str | bytes | x509.Certificate] = []

    # iterate on the certificates
    if isinstance(certs, str):
        # 'certs' is a PEM bundle
        certs_pem: list[str] = certs.split("-----END CERTIFICATE-----")
        for cert_pem in certs_pem:
            cert_pem += "-----END CERTIFICATE-----"
            if fmt == "pem":
                result.append(cert_pem)
            else:
                cert_x509: x509.Certificate = x509.load_pem_x509_certificate(data=cert_pem.encode(encoding="utf-8"))
                if fmt == "der":
                    result.append(cert_x509.public_bytes(encoding=Encoding.DER))
                else:
                    result.append(cert_x509)
    else:
        # 'certs' is a DER bundle
        offset: int = 0
        while offset < len(certs):
            # obtain the certificate length as encoded in the 4-byte header
            length: int = int.from_bytes(bytes=certs[offset:offset+4],
                                         byteorder="big")
            offset += 4
            # extract the certificate bytes
            cert_der: bytes = certs[offset:offset+length]
            offset += length
            if fmt == "der":
                result.append(cert_der)
            else:
                # load certificate
                cert_x509: x509.Certificate = x509.load_der_x509_certificate(data=cert_der)
                if fmt == "pem":
                    result.append(cert_x509.public_bytes(encoding=Encoding.PEM).decode(encoding="utf-8"))
                else:
                    result.append(cert_x509)
    return result


def cert_get_trusted(fmt: Literal["der", "pem", "x509"]) -> list[str | bytes | x509.Certificate]:
    """
    Retrieve the certificates in the trusted store of the host OS.

    The return format of the individual certificates is specified in *fmt*:
        - *der*: *Distinguished Encoding Rules*, binary as *bytes* (the default)
        - *pem*: *Privacy-Enhanced Mail*, text-based as *str*
        - *x509*: *cryptography.x509.Certificate*, object as non-serialized binary

    :param fmt: the output format to use for the individual certificates (defaults to *der*)
    :return: the list of certificates in the trusted store of the host OS
    """
    # initialize the return variable
    result: list[str | bytes | x509.Certificate] = []

    # read the trusted store
    ca_path: Path = Path(certifi.where())
    with ca_path.open("rb") as f:
        pem_data: bytes = f.read()

    # iterate on the certificates
    certs_pem: list[bytes] = pem_data.split(b"-----END CERTIFICATE-----")
    for cert_pem in certs_pem:
        cert_pem += b"-----END CERTIFICATE-----"
        if fmt == "pem":
            result.append(cert_pem.decode(encoding="utf-8"))
        else:
            cert_x509: x509.Certificate = x509.load_pem_x509_certificate(data=cert_pem)
            if cert_pem == "der":
                result.append(cert_x509.public_bytes(encoding=Encoding.DER))
            else:
                result.append(cert_x509)

    return result


def cert_verify_chain(cert_chain: list[x509.Certificate],
                      trusted_roots: list[x509.Certificate] = None,
                      errors: list[str] = None,
                      logger: Logger = None) -> bool:
    """
    Validate the certificates *cert_chain*, optionally using the trusted roots in *trusted_roots*.

    The verification is interrupted once the first problem is found.

    :param cert_chain: the certificate chain to validate
    :param trusted_roots: optional list of trusted roots to check the last certificate with
    :param errors: incidental errors (may be non-empty)
    :param logger: optional logger
    :return: True if *cert_chain* is valid, *False* otherwise
    """
    # define a local errors lista
    curr_errors: list[str] = []

    # check validity and BasicConstraints
    now: datetime = datetime.now(tz=UTC)
    err_msg: str | None = None
    for idx, cert in enumerate(iterable=cert_chain):
        if now < cert.not_valid_before:
            err_msg = f"Certificate '{cert.subject}' not yet valid"
        elif now > cert.not_valid_after:
            err_msg = f"Certificate '{cert.subject}' expired"
        elif idx > 0:  # intermediates
            bc: x509.BasicConstraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not bc.ca:
                err_msg = f"'{cert.subject}' is not a CA"
            elif isinstance(bc.path_length, int) and len(cert_chain) - idx - 1 > bc.path_length:
                err_msg = f"Path length constraint violated for '{cert.subject}'"
        if err_msg:
            break

    if not err_msg:
        # verify signatures
        for i in range(len(cert_chain) - 1):
            cert_verify_signature(cert=cert_chain[i],
                                  issuer=cert_chain[i + 1],
                                  errors=curr_errors,
                                  logger=logger)
            if curr_errors:
                break

        if not curr_errors and trusted_roots:
            # check last cert against trusted roots
            last_cert = cert_chain[-1]
            if not any(last_cert.subject == root.subject for root in trusted_roots):
                err_msg = "Chain does not terminate in a trusted root"

        # revocation checks
        if not err_msg:
            for idx, cert in enumerate(cert_chain[:-1]):  # leaf and intermediates
                issuer = cert_chain[idx + 1]
                if not cert_verify_revocation(cert=cert,
                                              issuer=issuer,
                                              logger=logger):
                    curr_errors.append(f"Certificate '{cert.subject}' has been revoked")
                    break
    if err_msg:
        if logger:
            logger.error(msg=err_msg)
        curr_errors.append(err_msg)

    if curr_errors and isinstance(errors, list):
        errors.extend(curr_errors)

    return not curr_errors


def cert_verify_signature(cert: x509.Certificate,
                          issuer: x509.Certificate,
                          errors: list[str] = None,
                          logger: Logger = None) -> bool:
    """
    Verify whether *cert*'s signature is valid.

    :param cert: the reference certificate
    :param issuer: the certificater issuer
    :param errors: incidental errors (may be non-empty)
    :param logger: optional logger
    :return: *True* if the signature is valid, *False* otherwise
    """
    # initialize the return variable
    result: bool = False

    # retrieve the certificate's public key
    public_key: PublicKeyTypes = issuer.public_key()

    # verify the signature
    try:
        if isinstance(public_key, RSAPublicKey):
            # determine the signature padding used
            sig_oid: str = cert.signature_algorithm_oid.dotted_string
            if sig_oid == "1.2.840.113549.1.1.10":  # RSASSA-PSS
                chosen_padding: padding.AsymmetricPadding = padding.PSS(
                    mgf=padding.MGF1(cert.signature_hash_algorithm),
                    salt_length=padding.PSS.MAX_LENGTH
                )
            else:
                chosen_padding: padding.AsymmetricPadding = padding.PKCS1v15()

            public_key.verify(cert.signature,
                              cert.tbs_certificate_bytes,
                              chosen_padding,
                              cert.signature_hash_algorithm)
        else:
            public_key.verify(cert.signature,
                              cert.tbs_certificate_bytes,
                              cert.signature_hash_algorithm)
        result = True
    except Exception as e:
        exc_err: str = exc_format(exc=e,
                                  exc_info=sys.exc_info())
        if logger:
            logger.error(msg=exc_err)
        if isinstance(errors, list):
            errors.append(exc_err)

    return result


def cert_verify_revocation(cert: x509.Certificate,
                           issuer: x509.Certificate,
                           logger: Logger = None) -> bool:
    """
    Verify whether *cert* is in good standing, that is, it has not been revoked.

    Two attempts are carried out to make sure ther certificate is still in good standing:
        - the appropriate *Certificate Revocation Lists* (CRLs) are inspected
        - the newer *Online Certificate Status Protocol* (OCSP) protocol is used

    :param cert: the reference certificate
    :param issuer: the certificate issuer
    :param logger: optional logger
    :return: *True* if the certificate is in good standing, *False* otherwise
    """
    # initialize the return variable
    result: bool = True

    # retrieve the CRL verification address
    crl_ext_value: x509.extensions.ExtensionTypeVar | None = None
    with suppress(x509.ExtensionNotFound):
        crl_ext: x509.extensions.Extension = cert.extensions.get_extension_for_class(
            extclass=x509.CRLDistributionPoints
        )
        crl_ext_value = crl_ext.value

    # check CRL distribution points
    for dp in crl_ext_value or []:
        for uri in dp.full_name:
            url: str = uri.value
            if url.startswith("http"):
                if logger:
                    logger.debug(msg=f"GET {url}")
                reply: requests.Response = requests.get(url=url,
                                                        timeout=None)
                if 200 >= reply.status_code <= 300:
                    if logger:
                        logger.debug("GET success")
                    crl_data: bytes = reply.content
                    crl: x509.CertificateRevocationList = x509.load_der_x509_crl(data=crl_data)
                    for revoked in crl:
                        if revoked.serial_number == cert.serial_number:
                            result = False
                            if logger:
                                logger.error(f"Certificate {cert.subject} has been revoked")
                elif logger:
                    logger.warning(msg=f"GET failure, status {reply.status_code}")

    # use OCSP protocol for further checking
    if result:
        aia_value: x509.extensions.ExtensionTypeVar | None = None
        with suppress(x509.ExtensionNotFound):
            aia: x509.extensions.Extension = cert.extensions.get_extension_for_class(
                extclass=x509.AuthorityInformationAccess
            )
            aia_value = aia.value

        ocsp_urls: list[Any] = [desc.access_location.value for desc in aia_value
                                if desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.1"]
        for url in ocsp_urls:
            print(f"Performing OCSP check at {url}")
            builder: OCSPRequestBuilder = OCSPRequestBuilder()
            # ruff: noqa: S303
            builder = builder.add_certificate(cert=cert,
                                              issuer=issuer,
                                              algorithm=hashes.SHA1())
            ocsp_request: x509.ocsp.OCSPRequest = builder.build()
            headers = {"Content-Type": "application/ocsp-request",
                       "Accept": "application/ocsp-response"}
            if logger:
                logger.debug(msg=f"GET {url}")
            reply: requests.Response = requests.post(url=url,
                                                     data=ocsp_request.public_bytes(encoding=Encoding.DER),
                                                     headers=headers,
                                                     timeout=None)
            if 200 >= reply.status_code <= 300:
                if logger:
                    logger.debug("GET success")
                ocsp_resp = load_der_ocsp_response(data=reply.content)

                if ocsp_resp.response_status.name == "successful":
                    cert_status = ocsp_resp.certificate_status.name
                    if cert_status == "revoked":
                        result = False
                        if logger:
                            logger.error(msg=f"Certificate '{cert.subject}' has been revoked")
                    elif logger:
                        logger.debug(msg=f"Certificate '{cert.subject}' status '{cert_status}'")
                elif logger:
                    logger.warning(msg=f"OCSP responder returned '{ocsp_resp.response_status.name}'")
            elif logger:
                logger.warning(msg=f"GET failure, status {reply.status_code}")

    return result
