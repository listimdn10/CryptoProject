from pymongo import MongoClient
import gridfs
from bson import ObjectId
import pprint
import datetime
import os
import base64
from io import BytesIO
from PyPDF2 import PdfWriter, PdfReader
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
import qrcode
from datetime import datetime as dt
import tkinter as tk
from tkinter import filedialog
import hashlib
import ctypes
import sys
import os
import base64
import pymongo
from io import BytesIO

# Load the shared library
lib = ctypes.CDLL('D:/MMH/CRYPTO_PROJECGT/MMHHHHH/oqs.dll')

# Define the function prototypes
lib.OQS_SIG_dilithium_5_keypair.restype = ctypes.c_int
lib.OQS_SIG_dilithium_5_keypair.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

lib.OQS_SIG_dilithium_5_sign.restype = ctypes.c_int
lib.OQS_SIG_dilithium_5_sign.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]

lib.OQS_SIG_dilithium_5_verify.restype = ctypes.c_int
lib.OQS_SIG_dilithium_5_verify.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]

# Constants for key and signature lengths
OQS_SIG_dilithium_5_length_public_key = 2592
OQS_SIG_dilithium_5_length_secret_key = 4864
OQS_SIG_dilithium_5_length_signature = 4595

def write_to_file(filename, data):
    with open(filename, 'wb') as f:
        f.write(base64.b64encode(data))

def read_from_file(filename):
    with open(filename, 'rb') as f:
        return base64.b64decode(f.read())

def generate_keys():
    pub_key = ctypes.create_string_buffer(OQS_SIG_dilithium_5_length_public_key)
    priv_key = ctypes.create_string_buffer(OQS_SIG_dilithium_5_length_secret_key)
    result = lib.OQS_SIG_dilithium_5_keypair(pub_key, priv_key)
    if result != 0:
        print("Key pair generation failed")
        return False
    write_to_file('public_key.b64', pub_key.raw)
    write_to_file('private_key.b64', priv_key.raw)
    print("Keys saved to files in base64 format")
    return True

def hash_data(data):
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.digest()

def sign_pdf(private_key_path, pdf_path, signature_path, account):
    priv_key_data = read_from_file(private_key_path)
    # Create QR watermark
    watermark = makeWatermark(account)
    signed_pdf_with_qr = makePdf(pdf_path, watermark)
    
    with open(signed_pdf_with_qr, 'rb') as f:
        pdf_qr = f.read()

    hashed_pdf_data = hash_data(pdf_qr)
    priv_key = ctypes.create_string_buffer(priv_key_data)
    signature = ctypes.create_string_buffer(OQS_SIG_dilithium_5_length_signature)
    sig_len = ctypes.c_size_t(0)
    result = lib.OQS_SIG_dilithium_5_sign(signature, ctypes.byref(sig_len), hashed_pdf_data, len(hashed_pdf_data), priv_key)
    if result != 0:
        print("Signing failed")
        return False
    write_to_file(signature_path, signature.raw[:sig_len.value])
    print("Signature saved to file in base64 format")
    return True

def verify_signature(public_key_path, pdf_path, signature_path):
    pub_key_data = read_from_file(public_key_path)
    with open(pdf_path, 'rb') as f:
        pdf_data = f.read()
    hashed_pdf_data = hash_data(pdf_data)
    signature_data = read_from_file(signature_path)
    pub_key = ctypes.create_string_buffer(pub_key_data)
    signature = ctypes.create_string_buffer(signature_data)
    result = lib.OQS_SIG_dilithium_5_verify(hashed_pdf_data, len(hashed_pdf_data), signature, len(signature_data), pub_key)
    if result != 0:
        print("Verification failed, PDF maybe changed")
        return False
    print("Signature verified successfully, PDF is safe")
    return True

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

def upload_to_gridfs(pub_key_path, sign_path, pdf_path, db_name='test'):
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client[db_name]
    fs = gridfs.GridFS(db)
    filename = os.path.basename(pdf_path)
    pub_key_data = read_from_file(pub_key_path)
    sign_data = read_from_file(sign_path)
    try:
        with open(pdf_path.replace(".pdf", "_signed.pdf"), 'rb') as f:       
            # Upload the file with metadata including the public key and signature
            file_id = fs.put(f, filename=filename.replace(".pdf", "_signed.pdf"), metadata={"public_key": base64.b64encode(pub_key_data).decode('utf-8'), "signature": base64.b64encode(sign_data).decode('utf-8')})
        print(f"File uploaded to MongoDB GridFS with file ID: {file_id}")
    except FileNotFoundError:
        print("Không tìm thấy file. Vui lòng kiểm tra lại đường dẫn.")
    except Exception as e:
        print(f"Đã xảy ra lỗi: {e}")
    return True

# Function to download file
def download_file(db, fs):
    files = db.fs.files.find()
    print("Danh sách các file trong cơ sở dữ liệu 'test':")
    file_list = []
    for file in files:
        pprint.pprint(f"Filename: {file['filename']}, Upload Date: {file['uploadDate']}")
        file_list.append(file)

    if not file_list:
        print("Không có file nào trong cơ sở dữ liệu.")
        return

    filename = input("Nhập tên file bạn muốn tải về: ")
    file = db.fs.files.find_one({"filename": filename})
    if not file:
        print(f"Không tìm thấy file với tên '{filename}' trong cơ sở dữ liệu.")
        return

    file_id = file['_id']
    output_filename = filename

    try:
        grid_out = fs.get(file_id)
        with open(output_filename, 'wb') as output_file:
            output_file.write(grid_out.read())

        print(f"File đã được tải về và lưu với tên {output_filename}")
    except gridfs.errors.NoFile:
        print(f"Không tìm thấy file với _id: {file_id} trong GridFS")
    except Exception as e:
        print(f"Đã xảy ra lỗi: {e}")

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

def publish_pdf(pub, pri, sign, account):
    # Select PDF file
    pdf_path = select_pdf_file()
    if not pdf_path:
        print("No file chosen!")
        return
    private_key_path = pri
    signature_path = sign
    pub_key_path = pub
    if sign_pdf(private_key_path, pdf_path, signature_path, account):
        print(f"PDF signed successfully and saved signature to {signature_path}")
    else:
        print("Failed to sign PDF.")
    if upload_to_gridfs(pub_key_path, signature_path, pdf_path, db_name='test'):
        print("Uploaded successfully.")
    else:
        print("Failed to upload.") 
    return True
    
# Function to choose and verify file
def verify_pdf(db, filename, public_key_path, signature_path):
    # Select PDF file
    pdf_path = select_pdf_file()
    if not pdf_path:
        print("No file chosen!")
        return
    
    filename = os.path.basename(pdf_path)
    
    file_record = db.fs.files.find_one({"filename": filename})
    if not file_record:
        print(f"Không tìm thấy tệp có tên '{filename}' trong cơ sở dữ liệu.")
        return
    
    metadata = file_record.get('metadata', {})
    if not metadata:
        print(f"Không tìm thấy metadata cho tệp '{filename}'.")
        return
    
    public_key_data = metadata.get('public_key', None).encode('utf-8')
    signature_data = metadata.get('signature', None).encode('utf-8')
    
    if not public_key_data or not signature_data:
        print(f"Không tìm thấy khóa công khai hoặc chữ ký trong metadata của tệp '{filename}'.")
        return

    # Lưu trữ dữ liệu khóa công khai vào tệp
    with open(public_key_path, 'wb') as public_key_file:
        public_key_file.write(public_key_data)
        print(f"Khóa công khai  được lưu vào '{public_key_path}'.")
    
    # Lưu trữ dữ liệu chữ ký vào tệp
    with open(signature_path, 'wb') as signature_file:
        signature_file.write(signature_data)
        print(f"Chữ ký được lưu vào '{signature_path}'.")

    # Verify the PDF
    verify_signature(public_key_path, pdf_path, signature_path)
    
    return True
    
# Main function
def main():
    client = MongoClient('mongodb://localhost:27017/')
    db = client['test']
    fs = gridfs.GridFS(db)

    while True:
        choice = input("Nhập: \n 'genkey' để tạo key \n 'publish' để Publish file nếu bạn có quyền admin \n 'download' để download \n 'verify' để xác minh file \n 'search_name' để tìm file theo tên \n 'search_date' để tìm file theo ngày \n 'exit' để thoát chương trình \n")
        if choice.lower() == 'genkey':
            if generate_keys():
                print("Keys generated successfully.")
            else:
                print("Failed to generate keys.")
        elif choice.lower() == 'publish':
            password = input("Nhập mật khẩu để publish file: ")
            if password == '@123admin':
                account = input("Publisher's name: ")
                private_key_path = input("Private key file: ")
                public_key_path = input("Public key file: ")
                signature_path = input("Signature filename: ")
                if not account:
                    print("Please enter the publisher's name!")
                    continue
                if publish_pdf(public_key_path, private_key_path, signature_path, account):
                    print("PDF published")
                else:
                    print("Failed to publish.")          
            else:
                print("Bạn không có quyền publish file.")
        elif choice.lower() == 'download':
            download_file(db, fs)
        elif choice.lower() == 'search_name':
            filename = input("Nhập tên file bạn muốn tìm: ")
            find_file_by_name(db, filename)
        elif choice.lower() == 'search_date':
            date_str = input("Nhập ngày bạn muốn tìm (YYYY-MM-DD): ")
            find_file_by_date(db, date_str)
        elif choice.lower() == 'verify':
            public_key_path = "pub.b64"
            signature_path = "sign.b64"
            if verify_pdf(db, fs, public_key_path, signature_path):
                print("Success to verified PDF.")
            else:
                print("Failed to verify PDF.")
        elif choice.lower() == 'exit':
            print("Chương trình kết thúc.")
            break
        else:
            print("Lựa chọn không hợp lệ.")

# Call the main function to execute the script
main()
