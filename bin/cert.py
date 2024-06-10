import subprocess
import os
import tkinter as tk
from tkinter import filedialog
from reportlab.pdfgen import canvas
from pymongo import MongoClient
import gridfs
from bson import ObjectId
import pprint
import datetime
import base64
from io import BytesIO
from PyPDF2 import PdfWriter, PdfReader
from reportlab.lib.units import mm
import qrcode
from datetime import datetime as dt
from pymongo import MongoClient
import gridfs


# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client['crypto_db']
fs = gridfs.GridFS(db)


cert_file = r'D:\\MMH\\CRYPTO_PROJECGT\\CryptoProject\\Openssl321-VS\\bin\\dilithium3_srv.crt'
pubkey_file = r'D:\\MMH\\CRYPTO_PROJECGT\\CryptoProject\\Openssl321-VS\\bin\\dilithium3_srv.pubkey'


# Function to generate CA key and self-signed certificate
def generate_ca_key_and_self_signed_certificate():
    try:
        command = 'openssl req -x509 -new -newkey dilithium3 -keyout root_CA.key -out root_CA.crt -nodes -subj "/CN=DigiCert" -days 365 -provider oqsprovider -config "C:\\Program Files\\Common Files\\SSL\\openssl.cnf"'
        subprocess.run(command, shell=True, check=True)
        print("CA key and self-signed certificate generated successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error generating CA key and self-signed certificate: {e}")
        print(e.stderr.decode())  

# Function to generate server key and certificate
def generate_server_key_and_certificate(): 
    try:
        genkey_command = 'openssl genpkey -algorithm dilithium3 -out dilithium3_srv.key -provider oqsprovider'
        subprocess.run(genkey_command, shell=True, check=True)

        req_command = 'openssl req -new -key dilithium3_srv.key -out dilithium3_srv.csr -nodes -subj "/CN=UIT" -provider oqsprovider -config "C:\\Program Files\\Common Files\\SSL\\openssl.cnf"'
        subprocess.run(req_command, shell=True, check=True)

        sign_command = 'openssl x509 -req -in dilithium3_srv.csr -out dilithium3_srv.crt -CA root_CA.crt -CAkey root_CA.key -CAcreateserial -days 365 -provider oqsprovider'
        subprocess.run(sign_command, shell=True, check=True)

        print("Server key and certificate generated successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error generating server key and certificate: {e}")
        print(e.stderr.decode())  


def detachPubKeyFromCert(cert_file, public_key_file):
    command = f"openssl x509 -in {cert_file} -pubkey -noout -out {public_key_file}"
    subprocess.run(command, shell=True, check=True)


# Function to sign data
def signData(privateKey, dataFile, signatureFile):
    command = f'openssl dgst -sha256 -sign "{privateKey}" -out "{signatureFile}" "{dataFile}"'
    result = subprocess.run(command, shell=True)
    return result.returncode == 0

import base64

   
def verifySignature(public_key_file, data_file, signature_base64):
    # Decode the base64-encoded signature
    signature = base64.b64decode(signature_base64.encode("utf-8"))
    
    # Write the decoded signature to a temporary binary file
    with open("temp_signature.bin", "wb") as sig_file:
        sig_file.write(signature)

    # Use the temporary signature file in the OpenSSL command
    command = f'openssl dgst -sha256 -verify "{public_key_file}" -signature "temp_signature.bin" "{data_file}"'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    # Remove the temporary signature file
    os.remove("temp_signature.bin")

    return "Verified OK" in result.stdout

def verify_file_in_db():
    file_path = select_pdf_file()
    if file_path:
        filename = os.path.basename(file_path)
        file_data = fs.find_one({"filename": filename})

        if file_data:
            metadata = file_data.metadata  # Access metadata directly as an attribute
            if metadata:
                public_key = metadata.get("public_key")
                signature_base64 = metadata.get("signature")

                if public_key and signature_base64:
                    with open("temp_public_key.pub", "w") as pub_file:
                        pub_file.write(public_key)
                    if verifySignature("temp_public_key.pub", file_path, signature_base64):
                        print("Signature verified successfully.")
                    else:
                        print("Signature verification failed.")
                    os.remove("temp_public_key.pub")
                else:
                    print("Public key or signature not found in metadata.")
            else:
                print("Metadata not found for the file.")
        else:
            print("File not found in the database.")
    else:
        print("No PDF file selected.")



# Function to create QR watermark
def makeWatermark(account):
    watermarkName = "qr.pdf"
    doc = canvas.Canvas(watermarkName)
    
    qr = qrcode.QRCode(version=2, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=4)
    now = dt.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    qr.add_data(f"Signed by: {account}\nDay/time: {dt_string}")
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_path = "temp_qr.png"
    img.save(img_path)
    doc.drawImage(img_path, 20 * mm, 40 * mm, 30 * mm, 30 * mm)
    doc.save()
    
    return watermarkName

# Function to merge PDF with watermark
def makePdf(src, watermark):
    merged = src.replace(".pdf", "_signed.pdf")
    
    with open(src, "rb") as input_file, open(watermark, "rb") as watermark_file:
        input_pdf = PdfReader(input_file)
        watermark_pdf = PdfReader(watermark_file)
        watermark_page = watermark_pdf.pages[0]
        
        output = PdfWriter()
        for i, page in enumerate(input_pdf.pages):
            if i == 0:
                page.merge_page(watermark_page)
            output.add_page(page)
        
        with open(merged, "wb") as merged_file:
            output.write(merged_file)
    
    return merged


# Function to select PDF file
def select_pdf_file():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
    return file_path




def upload_to_gridfs(filepath, public_key, signature):
    filename = os.path.basename(filepath)
    with open(filepath, "rb") as f:
        file_data = f.read()

    now = datetime.datetime.now()
    metadata = {
        "author": "admin",
        "public_key": public_key,
        "signature": signature
    }

    file_id = fs.put(file_data, filename=filename, metadata=metadata)


# Function to download PDF from MongoDB GridFS
def download_from_gridfs(file_id, download_path):
    file_data = fs.get(file_id)
    full_path = os.path.join(download_path, file_data.filename)
    
    with open(full_path, 'wb') as f:
        f.write(file_data.read())
    
    print(f"File {file_data.filename} downloaded successfully to {download_path}")

# Function to list PDFs in the database
def list_pdfs_in_db():
    files = fs.find()
    for file in files:
        print(f"ID: {file._id}, Filename: {file.filename}")


# Function to find file by name
def find_file_by_name(db, partial_filename):
    regex_pattern = f".*{partial_filename}.*"
    files = db.fs.files.find({"filename": {"$regex": regex_pattern}})
    
    if files:
        print(f"Các file có tên chứa '{partial_filename}':")
        for file in files:
            pprint.pprint(f"Filename: {file['filename']}, Upload Date: {file['uploadDate']}")
    else:
        print(f"Không có file nào có tên chứa '{partial_filename}' trong cơ sở dữ liệu.")

# Function to find file by date
def find_file_by_date(db, date_str):
    date = datetime.datetime.strptime(date_str, "%Y-%m-%d")
    files = db.fs.files.find({"uploadDate": {"$gte": date, "$lt": date + datetime.timedelta(days=1)}})
    
    if files:
        print("Các file tải lên vào ngày", date_str)
        for file in files:
            pprint.pprint(f"Filename: {file['filename']}, Upload Date: {file['uploadDate']}")
    else:
        print(f"Không có file nào được tải lên vào ngày {date_str} trong cơ sở dữ liệu.")


def upload_certificate_to_db(cert_path, cert_name):
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    cert_collection = db['certificates']
    cert_collection.insert_one({
        "name": cert_name,
        "certificate": cert_data,
        "uploadDate": datetime.datetime.now()
    })
    print(f"Certificate {cert_name} uploaded to database successfully.")


def main():
    generate_ca_key_and_self_signed_certificate()
    while True:
        print("1. create server key-cert")
        print("2. Sign pdf")
        print("3. Verify")
        print("4. upload to dtb")
        print("5. Download PDF")
        print("6. find by name")
        print("7. find by date YYYY-D-M")
        print("8. Exit")
        choice = input("Enter your choice: ")
        if choice == '1':
            password = input("Nhập mật khẩu nếu bạn có quyền admin: ")
            if password == '@123admin':
                generate_server_key_and_certificate()
                public_key = detachPubKeyFromCert(cert_file, pubkey_file)
                cert_name = input("Nhập tên cho Certificate máy chủ: ")
                upload_certificate_to_db("dilithium3_srv.crt", cert_name)
        elif choice == '2':
            password = input("Nhập mật khẩu nếu bạn có quyền admin: ")
            if password == '@123admin':
                
                pdf_file = select_pdf_file()
                if pdf_file:
                    private_key =  "dilithium3_srv.key"
                    signature_file = "signature"
                    watermark = makeWatermark("nhunhi")  
                    signed_pdf = makePdf(pdf_file, watermark)
                    # Call signData and check if signing was successful
                    if signData(private_key, signed_pdf, signature_file):
                        
                        print(f"PDF signed with QR code in: {signed_pdf}")
                    else:
                        print("Signing process failed. Please try again.")
                        return
                        
        elif choice == '3':
            verify_file_in_db()

        elif choice == '4':
            password = input("Nhập mật khẩu nếu bạn có quyền admin: ")
            if password == '@123admin':
                
                signed_pdf = select_pdf_file()
                with open("signature", "rb") as sig_file:
                    signature = base64.b64encode(sig_file.read()).decode("utf-8")
                
                with open("dilithium3_srv.pubkey", "r") as pubkey_file_obj:
                    public_key = pubkey_file_obj.read()
                
                upload_to_gridfs(signed_pdf, public_key, signature)
       
        elif choice == '5':
            list_pdfs_in_db()
            file_id = input("Enter the file ID to download: ")
            download_path = os.path.join(os.path.expanduser("~"), "Downloads")
            download_from_gridfs(ObjectId(file_id), download_path)

        elif choice == '6':
            filename = input("Nhập tên file bạn muốn tìm: ")
            find_file_by_name(db, filename)

        elif choice == '7':
            date_str = input("Nhập ngày bạn muốn tìm (YYYY-MM-DD): ")
            find_file_by_date(db, date_str)

        elif choice == '8':
            break
        else:
            print("Invalid choice. Please enter a valid option.")

if __name__ == "__main__":
    main()
