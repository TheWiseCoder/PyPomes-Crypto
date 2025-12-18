from __future__ import annotations  # allow forward references
from asn1crypto import cms
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7, pkcs12
from io import BytesIO
from logging import Logger
from pathlib import Path
from pypomes_core import file_get_data

from .crypto_base import CryptoBase
from .crypto_common import (
    CRYPTO_DEFAULT_HASH_ALGORITHM,
    HashAlgorithm, SignatureType, ChpHash,
    _chp_hash, _cms_build_cert_chain, _cms_verify_payload_hash,
    _cms_get_attr_value, _cms_get_content_info, _cms_get_payload, _cms_get_tsa_info,
    _crypto_get_signature_padding, _crypto_verify_signature
)


class CryptoPkcs7(CryptoBase):
    """
    Python code to extract crypto data from a PKCS#7 signature file.

    The crypto data is in *Cryptographic Message Syntax* (CMS), a standard for digitally signing, digesting,
    authenticating, andr encrypting arbitrary message content.

    These are the instance attributes:
        - p7x_bytes: bytes                 - the PKCS#7-compliant data in *DER* format
        - payload: bytes                   - the common payload (embedded or external)
        - signatures: list[SignatureInfo]  - data for list of signatures
    """
    # class-level logger
    logger: Logger | None = None

    def __init__(self,
                 p7x_in: BytesIO | Path | str | bytes,
                 doc_in: BytesIO | Path | str | bytes = None,
                 errors: list[str] = None) -> None:
        """
        Instantiate the *CryptoPkcs7* class, and extract the relevant crypto data.

        The natures of *p7x_in* and *doc_in* depend on their respective data types:
            - type *BytesIO*: is a byte stream
            - type *Path*: is a path to a file holding the data
            - type *bytes*: holds the data (used as is)
            - type *s'tr*: holds the data (used as utf8-encoded)

        The PKCS#7 data provided in *p7s_in* contains the A1 certificate and its corresponding
        public key, the certificate chain, the original payload (if *attached* mode), and the
        digital signature. The latter is always validated, and if a payload is provided in
        *doc_in* (*detached* mode), it is validated against its declared hash value.

        :param p7x_in: the PKCS#7 data in *DER* or *PEM* format
        :param doc_in: the original document data (the payload, required in *detached* mode)
        :param errors: incidental errors
        """
        super().__init__(doc_in=doc_in,
                         p7x_in=p7x_in)

        # define a local errors list
        curr_errors: list[str] = []

        # extract the base CMS structure
        content_info: cms.ContentInfo = _cms_get_content_info(p7s_bytes=self.p7x_bytes,
                                                              errors=curr_errors,
                                                              logger=CryptoPkcs7.logger)
        signed_data: cms.SignedData = content_info["content"] if content_info else None
        signer_infos: cms.SignerInfos | None = None
        if signed_data:
            # signatures in PKCS#7 are parallel, not chained, so they share the same payload
            self.payload_bytes = _cms_get_payload(signed_data=signed_data,
                                                  payload_bytes=self.payload_bytes,
                                                  errors=curr_errors,
                                                  logger=CryptoPkcs7.logger)
            if not curr_errors:
                signer_infos: cms.SignerInfos = signed_data["signer_infos"]

        # process the signatures
        for signer_info in (signer_infos or []):

            # extract the signature data
            signed_attrs: cms.CMSAttributes = signer_info["signed_attrs"]
            hash_algorithm: HashAlgorithm = HashAlgorithm(signer_info["digest_algorithm"]["algorithm"].native)
            signature: bytes = signer_info["signature"].native
            signature_algorithm: str = signer_info["signature_algorithm"]["algorithm"].native
            signature_timestamp: datetime = _cms_get_attr_value(cms_attrs=signed_attrs,
                                                                attr_type="signing_time")
            # extract and validate the payload hash
            computed_hash: bytes = _cms_verify_payload_hash(signed_attrs=signed_attrs,
                                                            payload=self.payload_bytes,
                                                            hash_alg=hash_algorithm,
                                                            errors=curr_errors,
                                                            logger=CryptoPkcs7.logger)
            if curr_errors:
                break

            # extract the certificate chain and the signer's certificate proper
            cert_data: tuple[list[bytes], int] = _cms_build_cert_chain(signed_data=signed_data,
                                                                       signer_info=signer_info)
            cert_chain: list[bytes] = cert_data[0]
            cert_ord: int = cert_data[1]
            signer_cert: x509.Certificate = x509.load_der_x509_certificate(data=cert_chain[cert_ord])
            public_key: PublicKeyTypes = signer_cert.public_key()
            cert_serial_number: int = signer_cert.serial_number
            signature_padding: padding.AsymmetricPadding = \
                _crypto_get_signature_padding(public_key=public_key,
                                              signature_alg=signature_algorithm,
                                              hash_alg=hash_algorithm)
            # identify the signer
            subject: x509.name.Name = signer_cert.subject
            signer_cn: str = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

            # TSA timestamp info (optional)
            tsa_data: tuple[datetime, str, str] = _cms_get_tsa_info(signer_info=signer_info,
                                                                    logger=CryptoPkcs7.logger)
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
                                     logger=CryptoPkcs7.logger)
            if curr_errors:
                break

            # build the signature's crypto data and save it
            sig_info: CryptoPkcs7.SignatureInfo = CryptoPkcs7.SignatureInfo(
                payload_ranges=[(0, len(self.payload_bytes))],
                payload_hash=computed_hash,
                hash_algorithm=hash_algorithm,
                signature=signature,
                signature_algorithm=signature_algorithm,
                signature_timestamp=signature_timestamp,
                public_key=public_key,
                signer_cn=signer_cn,
                signer_cert=signer_cert,
                cert_sn=cert_serial_number,
                cert_chain=cert_chain,
                tsa_timestamp=tsa_timestamp,
                tsa_policy=tsa_policy,
                tsa_sn=tsa_sn
            )
            self.signatures.append(sig_info)

        if curr_errors and isinstance(errors, list):
            errors.extend(curr_errors)

    @staticmethod
    def sign(doc_in: BytesIO | Path | str | bytes,
             pfx_in: BytesIO | Path | str | bytes,
             pfx_pwd: str | bytes = None,
             p7x_out: BytesIO | Path | str = None,
             embed_attrs: bool = True,
             hash_alg: HashAlgorithm = CRYPTO_DEFAULT_HASH_ALGORITHM,
             sig_type: SignatureType = SignatureType.DETACHED,
             errors: list[str] = None) -> CryptoPkcs7 | None:
        """
        Digitally sign a file in *attached* or *detached* format, using an A1 certificate.

        The natures of *doc_in* and *pfx_in* depend on their respective data types:
          - type *BytesIO*: is a byte stream
          - type *Path*: is a path to a file holding the data
          - type *bytes*: holds the data (used as is)
          - type *str*: holds the data (used as utf8-encoded)

        The signature is created as a PKCS#7/CMS compliant structure with full certificate chain.
        The parameter *sig_mode* determines whether the payload is to be embedded (*attached*),
        or left aside (*detached*).

        The parameter *embed_attrs* determines whether authenticated attributes should be embedded in the
        PKCS#7 structure (defaults to *True*). These are the attributes grouped under the label "signed_attrs"
        and cryptographically signed by the signer, meaning that, when they exist, the signature covers them,
        rather than the raw data. Besides the ones standardized in *RFC* publications, custom attributes
        may be created and given *OID* (Object Identifier) codes, to include application-specific metadata.
        These are some of the attributes:
            - *commitment_type_indication*: indicates the type of commitment (e.g., proof of origin)
            - *content_hint*: provides a hint about the content type or purpose
            - *content_type*: indicates the type of the signed content (e.g., *data*, *signedData*, *envelopedData*)
            - *message_digest*: contains the digest (usually, a SHA256 hash) of the payload (typically, *doc_in*)
            - *signer_location*: specifies the geographic location of the signer
            - *signing_certificate*: identifies the certificate used for signing
            - *signing_time*: the UTC time at which the signature was generated
            - *smime_capabilities*: lists the cryptographic capabilities supported by the signer

        If specified, *p7x_out* must be a *BytesIO* object, or contain a valid filepath. If the latter is
        provided without a file extension, it is set to *.p7m* or *.p7s*, depending on whether *sig_type*
        is specified as *attached* or *detached*, respectively. If the file already exists, it will be overwritten.

        :param doc_in: the document to sign
        :param pfx_in: the PKCS#12 (*.pfx*) data, containing A1 certificate and private key
        :param pfx_pwd: password for the *.pfx* data (if not provided, *pfx_in* is assumed to be unencrypted)
        :param p7x_out: path or byte stream to output the PKCS#7 file (optional, no output if not provided)
        :param embed_attrs: whether to embed the signed attributes in the PKCS#7 structure (defaults to *True*)
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
            doc_in: bytes = doc_bytes if sig_type == SignatureType.DETACHED else None
            crypto_pkcs7: CryptoPkcs7 = CryptoPkcs7(p7x_in=pkcs7_data,
                                                    doc_in=doc_in,
                                                    errors=curr_errors)
            if not curr_errors:
                result = crypto_pkcs7

                # output the PKCS#7 file
                if not curr_errors:
                    if isinstance(p7x_out, str):
                        p7x_out = Path(p7x_out)
                    if isinstance(p7x_out, Path):
                        # write the PKCS#7 data to a file
                        if not p7x_out.suffix:
                            suffix: str = ".p7m" if sig_type == SignatureType.ATTACHED else ".p7s"
                            p7x_out = p7x_out.with_suffix(suffix)
                        with p7x_out.open("wb") as out_f:
                            out_f.write(pkcs7_data)
                    elif isinstance(p7x_out, BytesIO):
                        # stream the PKCS#7 data to a file
                        p7x_out.write(pkcs7_data)

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
