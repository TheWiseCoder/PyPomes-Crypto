from asn1crypto import cms
from datetime import datetime
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
from cryptography.x509 import Certificate
from pathlib import Path
from pypomes_core import file_get_data


class CryptoPkcs7:
    """
    Python code to extract relevant data from a PKCS#7 signature file in DER or PEM format.
    """
    # instance attributes
    # p7s_bytes: bytes              - the PKCS#7 data
    # payload: bytes                - the payload (embedded or external)
    # payload_hash: bytes           - the payload hash
    # hash_algorithm: str           - the algorithm used to calculate the payload hash
    # signature: bytes              - the digital signature
    # signature_algorithm: str      - the algorithm used to generate the signature
    # signature_timestamp: datetime - the signature's timestamp
    # public_key: RSAPublicKey      - the RSA public key
    # public_bytes: bytes           - the serialized public key (in PEM format)
    # cert_chain: list[bytes]       - the serialized X509 certificate chain (in PEM format)

    def __init__(self,
                 p7s_file: Path | str | bytes,
                 p7s_payload: str | bytes = None) -> None:
        """
        Instantiate the PKCS#7 crypto class, and extract the relevant data.

        If a detached payload is specified in *p7s_payload*, it is validated against the
        payload's declared hash value.

        :param p7s_file: path for a PKCS#7 file in DER format, or the bytes thereof
        :param p7s_payload: a payload file path, or the bytes thereof
        :raises ValueError: if the payload is inconsistent with its declared hash value
        :raises InvalidSignature: if the digital signature is invalid
        """
        # obtain the PKCS#7 file data
        self.p7s_bytes: bytes = file_get_data(file_data=p7s_file)

        # extract the certificate chain and serialize it in PEM format
        certs: list[Certificate] = load_der_pkcs7_certificates(data=self.p7s_bytes)
        self.cert_chain: list[bytes] = [cert.public_bytes(encoding=Encoding.PEM)
                                        for cert in certs]

        #  extract the public key and serialize it in PEM format
        cert: Certificate = certs[0]
        # 'cert.public_key()' may return one of:
        #   DSAPublicKey, RSAPublicKey, EllipticCurvePublicKey,
        #   Ed25519PublicKey, Ed448PublicKey, X25519PublicKey, X448PublicKey
        self.public_key: RSAPublicKey = cert.public_key()
        self.public_bytes: bytes = self.public_key.public_bytes(encoding=Encoding.PEM,
                                                                format=PublicFormat.SubjectPublicKeyInfo)
        # extract the needed structures
        content_info: cms.ContentInfo = cms.ContentInfo.load(encoded_data=self.p7s_bytes)
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
            self.payload: bytes = file_get_data(file_data=p7s_payload)
        else:
            # no, extract the embedded payload
            self.payload: bytes = signed_data["encap_content_info"]["content"].native

    def verify_hash(self) -> bool:
        """
        Verify whether the declared hash value effectively matches the payload.

        :return: 'True' if the hash value matches the payload, 'False' otherwise
        """
        from crypto_pomes import crypto_hash
        effective_hash: bytes = crypto_hash(msg=self.payload,
                                            alg=self.hash_algorithm)
        return effective_hash == self.payload_hash

    def verify_signature(self) -> bool:
        """
        Verify whether the digital signature is valid.

        :return: 'True' if the digital signature is valid, 'False' otherwise
        """
        # verify the digital signature
        result: bool
        try:
            self.public_key.verify(signature=self.signature,
                                   data=self.payload,
                                   padding=PKCS1v15(),
                                   algorithm=SHA256())
            result = True
        except InvalidSignature:
            result = False

        return result
