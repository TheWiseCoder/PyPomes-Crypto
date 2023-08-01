from asn1crypto import cms
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7, Encoding, PublicFormat


class Pkcs7Data:
    """Python code to extract relevant data from a PKCS#7 signature file."""

    # class attributes
    payload: bytes                       # the original payload
    payload_hash: bytes                  # the payload hash
    hash_algorithm: str                  # the algorithm used to calculate the payload hash
    signature: bytes                     # the digital signature
    signature_algorithm: str             # the algorithm used to generate the signature
    signature_timestamp: datetime        # the signature's timestamp
    public_key: bytes                    # the serialized public key (in PEM format)
    cert_chain: list[bytes]              # the serialized X509 certificate chain (in PEM format)

    def __init__(self, p7s_file: str | bytes):
        """
        Instantiate the PKCS#7 crypto class, and extract the relevant data.

        :param p7s_file: a p7s file path or the p7s file bytes
        """
        # is the input argument a file path ?
        if isinstance(p7s_file, str):
            # yes, load pkcs#7 data from file
            with open(p7s_file, "rb") as f:
                p7s_bytes: bytes = f.read()
        else:
            # no, it holds the pkcs#7 data
            p7s_bytes = p7s_file

        # extract the certificate chain and serialize it in PEM format
        self.cert_chain = []
        certs: list[x509.Certificate] = pkcs7.load_der_pkcs7_certificates(p7s_bytes)
        for cert in certs:
            self.cert_chain.append(cert.public_bytes(Encoding.PEM))

        #  extract the public key and serialize it in PEM format
        cert: x509.Certificate = certs[-1]
        self.public_key = cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        # extract the needed structures
        content_info: cms.ContentInfo = cms.ContentInfo.load(p7s_bytes)
        signed_data: cms.SignedData = content_info["content"]
        signer_info: cms.SignerInfo = signed_data["signer_infos"][0]

        # extract the payload (None if payload is detached)
        self.payload = signed_data["encap_content_info"]["content"].native

        # extract the remaining components
        self.signature = signer_info[""].native
        self.signature_algorithm = signer_info["signature_algorithm"]["algorithm"].native
        self.hash_algorithm = signer_info["digest_algorithm"]["algorithm"].native

        signed_attrs = signer_info["signed_attrs"]
        for signed_attr in signed_attrs:
            match signed_attr["type"].native:
                case "message_digest":
                    self.payload_hash = signed_attr["values"][0].native
                case "signing_time":
                    self.signature_timestamp = signed_attr["values"][0].native
