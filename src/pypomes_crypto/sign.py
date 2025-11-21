
import io
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers, timestamps

# --- Configuration ---
# 1. Path to your input PDF file
INPUT_PDF = "document_to_sign.pdf"
# 2. Path to your PKCS#12 file containing the signing key and certificate
PFX_FILE = "signer_key_cert.pfx"
# 3. Passphrase for your PKCS#12 file
PFX_PASSPHRASE = b"your_password"
# 4. URL of a publicly available RFC 3161 Time Stamping Authority (TSA)
TSA_URL = "http://tsa.example.com/api"  # Replace with a real TSA URL
# 5. Output file name
OUTPUT_PDF = "document_signed_with_tsa.pdf"

# --- 1. Load the Signer ---
# Load the signing certificate and key from a PKCS#12 file
signer = signers.SimpleSigner.load_pkcs12(pfx_file=PFX_FILE, passphrase=PFX_PASSPHRASE)

# --- 2. Create the TimeStamper ---
# Instantiate the HTTPTimeStamper client using the TSA server URL
tsa_client = timestamps.HTTPTimeStamper(
    url=TSA_URL,
    timeout=10,  # Optional: Set a timeout for the network request
)

# --- 3. Prepare the PDF and Sign ---
with open(INPUT_PDF, "rb") as doc:
    # Use IncrementalPdfFileWriter to prepare the PDF for signing
    writer = IncrementalPdfFileWriter(doc)

    # Define the signature metadata
    # The 'field_name' specifies the PDF signature field to use (will be created if it doesn't exist)
    sig_meta = signers.PdfSignatureMetadata(
        field_name="Signature1",
        # Set the PAdES profile to B-T (Baseline-Timestamp) to ensure
        # the timestamp is included for long-term validation.
        sig_type=signers.SigType.PAdES,
    )

    # Sign the PDF, passing the TSA client in the 'timestamper' parameter
    # The output will be a BytesIO object with the signed PDF content
    output_buf = signers.sign_pdf(
        pdf_out=writer,
        signature_meta=sig_meta,
        signer=signer,
        timestamper=tsa_client,  # This is the key to adding the TSA timestamp
    )

# --- 4. Write the Signed PDF to a File ---
with open(OUTPUT_PDF, "wb") as out_f:
    out_f.write(output_buf.read())

print(f"Successfully signed '{INPUT_PDF}' and saved to '{OUTPUT_PDF}' with a TSA timestamp.")