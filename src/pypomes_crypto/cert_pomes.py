import sys
import certifi
import requests
from contextlib import suppress
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response
from datetime import datetime, UTC
from logging import Logger
from pathlib import Path
from pypomes_core import exc_format
from typing import Any

from .crypto_common import ChpPublicKey


def cert_load_trusted() -> list[x509.Certificate]:
    """
    Retrieve the certificates in the trusted store of the host OS.

    :return: the list of certificates in the trtusted store of the host OS
    """
    # initialize the return variable
    result: list[x509.Certificate] = []

    # read the trusted store
    ca_path: Path = Path(certifi.where())
    with ca_path.open("rb") as f:
        pem_data: bytes = f.read()

    # iterate on the certificates
    for cert in pem_data.split(b"-----END CERTIFICATE-----"):
        if b"-----BEGIN CERTIFICATE-----" in cert:
            cert += b"-----END CERTIFICATE-----"
            result.append(x509.load_pem_x509_certificate(data=cert))

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
    public_key: ChpPublicKey = issuer.public_key()

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
    :param issuer: the certificater issuer
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
