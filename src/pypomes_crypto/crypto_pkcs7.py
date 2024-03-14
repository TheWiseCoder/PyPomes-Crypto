from asn1crypto import cms
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7, Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pypomes_core import file_get_data

from .crypto_common import crypto_compute_hash


class CryptoPkcs7:
    """Python code to extract relevant data from a PKCS#7 signature file in DER format."""

    def __init__(self, p7s_file: str | bytes, p7s_payload: str | bytes = None) -> None:
        """
        Instantiate the PKCS#7 crypto class, and extract the relevant data.

        If a detached payload is specified in *p7s_payload*, it is validated against the
        payload hash information.

        :param p7s_file: path for a PKCS#7 file in DER format, or the bytes thereof
        :param p7s_payload: a payload file path, or the bytes thereof
        :raises ValueError: if the payload is inconsistent with its hash value
        """
        # instance attributes
        # self.payload: bytes                - the embedded payload
        # self.payload_hash: bytes           - the payload hash
        # self.hash_algorithm: str           - the algorithm used to calculate the payload hash
        # self.signature: bytes              - the digital signature
        # self.signature_algorithm: str      - the algorithm used to generate the signature
        # self.signature_timestamp: datetime - the signature's timestamp
        # self.public_key: bytes             - the serialized public key (in PEM format)
        # self.cert_chain: list[bytes]       - the serialized X509 certificate chain (in PEM format)

        # obtain the PKCS#7 file data
        p7s_bytes: bytes = file_get_data(p7s_file)

        # extract the certificate chain and serialize it in PEM format
        certs: list[x509.Certificate] = pkcs7.load_der_pkcs7_certificates(p7s_bytes)
        self.cert_chain: list[bytes] = [cert.public_bytes(Encoding.PEM) for cert in certs]

        #  extract the public key and serialize it in PEM format
        cert: x509.Certificate = certs[-1]
        # 'cert.public_key()' may return one of:
        #   DSAPublicKey, RSAPublicKey, EllipticCurvePublicKey,
        #   Ed25519PublicKey, Ed448PublicKey, X25519PublicKey, X448PublicKey
        public_key: RSAPublicKey = cert.public_key()
        self.public_key: bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        # extract the needed structures
        content_info: cms.ContentInfo = cms.ContentInfo.load(p7s_bytes)
        signed_data: cms.SignedData = content_info["content"]
        signer_info: cms.SignerInfo = signed_data["signer_infos"][0]

        # extract the needed components
        self.signature: bytes = signer_info["signature"].native
        self.signature_algorithm: str = signer_info["signature_algorithm"]["algorithm"].native
        self.hash_algorithm: str = signer_info["digest_algorithm"]["algorithm"].native

        signed_attrs = signer_info["signed_attrs"]
        for signed_attr in signed_attrs:
            match signed_attr["type"].native:
                case "message_digest":
                    self.payload_hash: bytes = signed_attr["values"][0].native
                case "signing_time":
                    self.signature_timestamp: datetime = signed_attr["values"][0].native

        # has a detached payload been specified ?
        if p7s_payload:
            # yes, load it
            self.payload: bytes = file_get_data(p7s_payload)
            # validate it
            payload_hash: bytes = crypto_compute_hash(self.payload, self.hash_algorithm)
            if payload_hash != self.payload_hash:
                raise ValueError("The payload's hash value does not match its content")
        else:
            # no, extract the embedded payload
            self.payload: bytes = signed_data["encap_content_info"]["content"].native
