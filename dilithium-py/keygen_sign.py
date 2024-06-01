import os
import shutil
import base64
import binascii
from io import BytesIO
from dilithium import Dilithium3
from PyPDF2 import PdfWriter, PdfReader

def generate_dilithium_signature_from_file(file_path):
    # Check if the file exists
    if not os.path.exists(file_path):
        print("File not found.")
        return None, None, None
    
    # Read the data from the file
    with open(file_path, "rb") as file:
        data = file.read()
    
    # Generate a key pair
    pk, sk = Dilithium3.keygen()
    
    # Sign the data using the private key
    signature = Dilithium3.sign(sk, data)
    
    return pk, signature, data

def save_signed_pdf(output_path, pdf_data, signature):
    # Write the signed PDF data to a file
    with open(output_path, "wb") as file:
        file.write(pdf_data)
    
    # Append the signature to the file
    with open(output_path, "ab") as file:
        file.write(signature)

def attach_digital_signature(pdf_path, signature_base64):
    # Read the PDF data
    with open(pdf_path, 'rb') as file:
        pdf_data = file.read()
    
    # Create a PDF writer object
    writer = PdfWriter()
    
    # Add the original PDF content
    reader = PdfReader(BytesIO(pdf_data))
    for page in reader.pages:
        writer.add_page(page)
    
    # Add the digital signature to the metadata
    writer.add_metadata({
        '/Signature': signature_base64
    })
    
    # Write the updated PDF content to the output file
    with open(pdf_path, 'wb') as file:
        writer.write(file)
    
    print("Digital signature attached to the PDF.")

# Prompt the user to enter the path of the PDF file
file_path = r"D:\MMH\DOANMMH\VanBan2.pdf"

# Generate the Dilithium digital signature
public_key, signature, pdf_data = generate_dilithium_signature_from_file(file_path)

if public_key and signature and pdf_data:
    # Convert public key and signature to Base64 for better readability
    public_key_base64 = base64.b64encode(public_key).decode('utf-8')
    signature_base64 = base64.b64encode(signature).decode('utf-8')
    
    print("Public Key (Base64):", public_key_base64)
    print("Signature (Base64):", signature_base64)
    print("Dilithium digital signature generated successfully.")
    
    # Specify the path to save the signed PDF file
    output_pdf_path = r"C:\Users\Admin\Downloads\signed.pdf"

    # Save the signed PDF file
    save_signed_pdf(output_pdf_path, pdf_data, signature)

    print(f"Signed PDF saved to: {output_pdf_path}")

    # Attach the digital signature to the PDF
    attach_digital_signature(output_pdf_path, signature_base64)