from PyPDF2 import PdfReader

def is_pdf_signed(pdf_path):
    try:
        # Open the PDF file
        with open(pdf_path, "rb") as file:
            pdf_reader = PdfReader(file)
            
            # Get the document metadata
            metadata = pdf_reader.metadata
            
            # Check if the '/Signature' key is present in the metadata
            if '/Signature' in metadata:
                return True
            else:
                return False
    except Exception as e:
        print(f"An error occurred while checking the PDF: {e}")
        return False

# Specify the path to the signed PDF file
signed_pdf_path = r"C:\Users\Admin\Downloads\signed.pdf"

# Check if the signed PDF file is signed
if is_pdf_signed(signed_pdf_path):
    print("The PDF is signed.")
else:
    print("The PDF is not signed.")
