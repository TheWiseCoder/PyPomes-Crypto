import sys
from asn1crypto import cms, tsp, x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from datetime import datetime
from enum import StrEnum, auto
from logging import Logger
from pypomes_core import APP_PREFIX, env_get_enum, exc_format
from typing import Any, Final


class HashAlgorithm(StrEnum):
    """
    Supported hash algorithms.
    """
    MD5 = auto()
    BLAKE2B = auto()
    BLAKE2S = auto()
    SHA1 = auto()
    SHA224 = auto()
    SHA256 = auto()
    SHA384 = auto()
    SHA512 = auto()
    SHA3_224 = auto()
    SHA3_256 = auto()
    SHA3_384 = auto()
    SHA3_512 = auto()
    SHAKE_128 = auto()
    SHAKE_256 = auto()


class SignatureType(StrEnum):
    """
    Types of cryptographic signatures in documents.
    """
    ATTACHED = auto()
    DETACHED = auto()
    PADES = auto()


ChpHash = hashes.SHA224 | hashes.SHA256 | hashes.SHA384 | hashes.SHA512

CRYPTO_DEFAULT_HASH_ALGORITHM: Final[HashAlgorithm] = \
    env_get_enum(key=f"{APP_PREFIX}_CRYPTO_DEFAULT_HASH_ALGORITHM",
                 enum_class=HashAlgorithm,
                 def_value=HashAlgorithm.SHA256)


def _chp_hash(alg: HashAlgorithm | str,
              errors: list[str] = None,
              logger: Logger = None) -> ChpHash:
    """
    Construct the *cryptography* package's hash object corresponding top *hash_alg*.

    The hash object is an instance of *cryptography.hazmat.primitives.hashes.<hash>*

    :param alg: the hash algorithm
    :param errors: incidental errors
    :return: the *Crypto* package's hash object, or *None* if error
    """
    result: ChpHash | None = None
    match alg:
        case HashAlgorithm.SHA224:
            result = hashes.SHA224()
        case HashAlgorithm.SHA256:
            result = hashes.SHA256()
        case HashAlgorithm.SHA384:
            result = hashes.SHA384()
        case HashAlgorithm.SHA512:
            result = hashes.SHA512()
        case _:
            msg = f"Hash algorithm not supported: '{alg}'"
            if logger:
                logger.error(msg=msg)
            if isinstance(errors, list):
                errors.append(msg)

    return result


def _cms_build_cert_chain(signed_data: cms.SignedData,
                          signer_info: cms.SignerInfo) -> tuple[list[bytes], int]:
    """
    Build the certificate chain as a list of *DER* bytes, indicating the ordinal position of the proper certificate.

    The proper certificate is the one in the certificate chain in *signed_data* directly linker to the signer
    in *signer_info*. If not found, the last ordinal position isindicated.

    :param signed_data: the reference CMS *SignedData* structure
    :param signer_info: the reference CMS *SignerInfo* structure
    :return: the cartificate chain, with the ordina position of the proper certificate
    """
    # initialize the return variables
    result_ord: int = -1
    result_chain: list[bytes] = []

    signer_id: cms.SignerIdentifier = signer_info["sid"]
    certs: cms.CertificateSet = signed_data["certificates"]
    for cert_ord, cert_choice in enumerate(certs):
        # noinspection PyUnresolvedReferences
        cert: x509.Certificate = cert_choice.chosen
        der_bytes: bytes = cert.dump()
        result_chain.append(der_bytes)
        if result_ord < 0:
            if signer_id.name == "issuer_and_serial_number":
                # match issuer and serial number
                if cert.issuer == signer_id.chosen["issuer"] and \
                   cert.serial_number == signer_id.chosen["serial_number"].native:
                    result_ord = cert_ord
            elif signer_id.name == "subject_key_identifier":
                # extract SKI from certificate extensions
                for ext in cert["tbs_certificate"]["extensions"]:
                    if ext["extn_id"].native == "subject_key_identifier" and \
                            ext["extn_value"].native == signer_id.chosen.native:
                        result_ord = cert_ord
                        break

    return result_chain, result_ord


def _cms_dump_attrs(cms_attrs: cms.CMSAttributes) -> bytes:
    """
    Dump the *CMSAttributes* structure in *cms_attrs* to bytes, after sorting them in canonical *DER* order.

    This is necessary, because the *Cryptographic Message Syntax* (CMS) standard requires attribute sets to be
    sorted in *DER* canonical order before being dumped, so that operations such as hashing yield consistent results.

    :param cms_attrs: the *CMSAttributes* to sort and dump
    :return: the *DER* bytes obtained from dumping *cms_attrs*
    """
    # sort the attribute set
    sorted_attrs: list[cms.CMSAttribute] = sorted(cms_attrs,
                                                  key=lambda attr: attr.dump())
    # recreate the CMSAttributes object
    cms_attrs = cms.CMSAttributes(sorted_attrs)

    return cms_attrs.dump()


def _cms_get_attr_value(cms_attrs: cms.CMSAttributes,
                        attr_type: str) -> Any:
    """
    Retrieve the native value of the *CMSAttribute* object in *cms_attrs* with type *attr_type*.

    :param cms_attrs: the *CMSAttributes* to inspect
    :param attr_type: the reference type
    :return: the native value of the *CMSAttribute* object with type *attr_type*, or *None* if not found
    """
    # initialize the return variable
    result: Any = None

    # traverse the attributes set
    for cms_attr in cms_attrs:
        cms_type: str = cms_attr["type"].native
        if cms_type == attr_type:
            result = cms_attr["values"][0].native
            break

    return result


def _cms_get_content_info(p7s_bytes: bytes,
                          errors: list[str],
                          logger: Logger | None) -> cms.ContentInfo | None:
    """
    Retrieve the CMS *ContentInfo* structure from the *PKCS#7* data *p7s_bytes*.

    :param p7s_bytes: the *PKCS#7*-compliant data
    :param errors: incidental errors
    :param logger: optional logger
    :return: the *ContentInfo* structure, or *None* if error
    """
    # initialize the return vaiable
    result: cms.ContentInfo | None = None

    try:
        content_info = cms.ContentInfo.load(encoded_data=p7s_bytes)
        if "content_type" in content_info and \
                content_info["content_type"].native == "signed_data":
            result = content_info
        else:
            msg = "'p7_data' does not hold a valid PKCS#7 file"
            if logger:
                logger.error(msg=msg)
            errors.append(msg)
    except Exception as e:
        msg: str = exc_format(exc=e,
                              exc_info=sys.exc_info())
        if logger:
            logger.error(msg=msg)
        errors.append(msg)

    return result


def _cms_get_payload(signed_data: cms.SignedData,
                     payload_bytes: bytes,
                     errors: list[str],
                     logger: Logger | None) -> bytes | None:
    """
    Retrieve the payload associated with the CMS *SignedData* structure in *signed_data*.

    If the payload is not embedded in the CMS structure, is is assumed to have been obtained from the
    original document data.

    :param signed_data: the reference *SignedData* structure
    :param payload_bytes: the original document data (the payload, if detached mode)
    :param errors: incidental errors
    :param logger: optional logger
    :return: the payload associated with *signed_data*, or *None* if no payload was retrieved
    """
    # attempt to obtain the embedded payload
    result: bytes = signed_data["encap_content_info"]["content"].native

    err_msg: str | None = None
    if not result:
        if payload_bytes:
            result = payload_bytes
        else:
            err_msg = "For detached mode, a payload file must be provided"
    elif payload_bytes and result != payload_bytes:
        err_msg: str = "The stored payload does note match the provided payload file"

    if err_msg:
        if logger:
            logger.error(msg=err_msg)
        errors.append(err_msg)

    return result


def _cms_verify_payload_hash(signed_attrs: cms.CMSAttributes,
                             payload: bytes,
                             hash_alg: HashAlgorithm,
                             errors: list[str],
                             logger: Logger | None) -> bytes:
    """
    Compute the payload hash and compare it with the stored value.

    :param signed_attrs: the *CMSAttributes* set cntaining the authenticated data
    :param payload: the reference payload
    :param errors: incidental errors
    :param logger: optional logger
    :return: tha computed payload hash, or *None* if error
    """
    from .crypto_pomes import crypto_hash

    # initialize the return variable
    result: bytes | None = None

    computed_hash: bytes = crypto_hash(msg=payload,
                                       alg=hash_alg)
    stored_hash: bytes = _cms_get_attr_value(cms_attrs=signed_attrs,
                                             attr_type="message_digest")
    if not stored_hash:
        if logger:
            logger.warning(msg="No payload digest found in CMS structure")
    elif computed_hash == stored_hash:
        result = computed_hash
    else:
        # hashes do not match
        msg: str = "Computed and stored digest values do not match"
        if logger:
            logger.error(msg=msg)
            errors.append(msg)

    return result


def _cms_get_tsa_info(signer_info: cms.SignerInfo,
                      logger: Logger | None) -> tuple[datetime, str, str]:
    """
    Retrieve the *Time Stamping Authority* (TSA) data from the CMS *SignerInfo* structure in *signer_info*.

    :param signer_info: the reference CMS *SignerInfo* structure
    :param logger: optional logger
    :return: the TSA's timestamp, policy and serial number, or *None* values if not found
    """
    # initialize the return variables
    result_timestamp: datetime | None = None
    result_policy: str | None = None
    result_sn: str | None = None

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
                result_timestamp = tst_info["gen_time"].native
                result_policy = tst_info["policy"].native
                result_sn = hex(tst_info["serial_number"].native)
                break

            except Exception as e:
                # unable to obtain TAS data: error parsing token
                if logger:
                    msg: str = exc_format(exc=e,
                                          exc_info=sys.exc_info())
                    logger.warning(msg=msg)
                break

    return result_timestamp, result_policy, result_sn


def _crypto_get_signature_padding(public_key: PublicKeyTypes,
                                  signature_alg: str,
                                  hash_alg: HashAlgorithm) -> padding.AsymmetricPadding:
    """
    Retrieve the signature padding mechanism in/to use.
    """
    # initialize the return variable
    result: padding.AsymmetricPadding | None = None

    if isinstance(public_key, rsa.RSAPublicKey):
        if "pss" in signature_alg:
            result = padding.PSS(mgf=padding.MGF1(algorithm=_chp_hash(alg=hash_alg)),
                                 salt_length=padding.PSS.MAX_LENGTH)
        else:
            result: padding.AsymmetricPadding = padding.PKCS1v15()

    return result


def _crypto_verify_signature(public_key: PublicKeyTypes,
                             signature: bytes,
                             signature_padding: padding.AsymmetricPadding,
                             signer_cn: str,
                             signed_attrs: cms.CMSAttributes,
                             payload_hash: bytes,
                             hash_algorithm: HashAlgorithm,
                             errors: list[str] | None,
                             logger: Logger | None) -> bool:
    """
    Verify the digital signature as per the data provided.

    :param public_key: the RSA public key object
    :param signature: the signature to be verified
    :param signature_padding: the padding mechanism used when signing
    :param signer_cn: the signer's common name
    :param signed_attrs: the authenticated *CMSAttributes* set
    :param payload_hash: the computed payload digest
    :param hash_algorithm: the algorithm used to compute the payload hash
    :param errors: incidental errors
    :param logger: optional logger
     :return: *True* if the signature is valid, or *False* otherwise
    """
    # initialize the return variable
    result: bool = False
    if signed_attrs:
        from .crypto_pomes import crypto_hash
        # HAZARD - notes on 'signed_attrs':
        #   - when it exists, the signature covers its attributes, not the payload
        #   - it was sorted in DER canonical order before being signed
        #   - it was kept in storage in the insert order of its attributes
        #   - 'dump()' fails to sort it in DER canonical order
        #   - a manual sort is thus required, for the verification to succeed
        attrs_dump: bytes = _cms_dump_attrs(cms_attrs=signed_attrs)
        payload_hash = crypto_hash(msg=attrs_dump,
                                   alg=hash_algorithm)

    chp_hash: ChpHash = _chp_hash(alg=hash_algorithm)
    try:
        if signature_padding:
            public_key.verify(signature=signature,
                              data=payload_hash,
                              padding=signature_padding,
                              algorithm=Prehashed(chp_hash))
        else:
            public_key.verify(signature=signature,
                              data=payload_hash,
                              algorithm=Prehashed(chp_hash))
        result = True
    except Exception as e:
        msg: str = exc_format(exc=e,
                              exc_info=sys.exc_info()) + f" signed by {signer_cn}"
        if errors:
            if logger:
                logger.error(msg=msg)
            errors.append(msg)
        elif logger:
            logger.warning(msg=msg)

    return result
