from flask import Flask, render_template, request, redirect, url_for, flash
from flask import Flask, request, render_template, make_response, flash, redirect, url_for
from flask import Flask, render_template, request, flash, redirect, url_for, send_file

from flask import send_file, request
import gridfs
import os
import base64
from io import BytesIO
import ctypes
from PyPDF2 import PdfWriter, PdfReader
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
import qrcode
import tkinter as tk
from tkinter import filedialog
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from pymongo import MongoClient
from bson import ObjectId
import pprint
from io import BytesIO
from datetime import datetime as dt
import hashlib
import sys
import pymongo
import tempfile
from tkinter import filedialog
from bson.objectid import ObjectId


from werkzeug.utils import secure_filename  # Add this import

# Load the shared library
lib = ctypes.CDLL('D:/MMH/CRYPTO_PROJECGT/CryptoProject/oqs.dll')

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

app = Flask(__name__)
app.secret_key = 'supersecretkey'

client = MongoClient('mongodb://localhost:27017/')
db = client['test']
fs = gridfs.GridFS(db)

# Helper functions from your original code

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

def publish_pdf(pub, pri, sign, account):
    # Select PDF file
    pdf_path = select_pdf_file()
    if not pdf_path:
        print("No file chosen!")
        return
    private_key_path = pri
    signature_path = sign
    pub_key_path = pub            
    if generate_keys():
        print("Keys generated successfully.")
    else:
        print("Failed to generate keys.")   
    if sign_pdf(private_key_path, pdf_path, signature_path, account):
        print(f"PDF signed successfully and saved signature to {signature_path}")
    else:
        print("Failed to sign PDF.")
    if upload_to_gridfs(pub_key_path, signature_path, pdf_path, db_name='test'):
        print("Uploaded successfully.")
    else:
        print("Failed to upload.") 
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
    return [{"filename": file['filename'], "uploadDate": file['uploadDate']} for file in files]

# Function to find file by date
def find_file_by_date(db, date_str):
    date = datetime.strptime(date_str, "%Y-%m-%d")
    files = db.fs.files.find({"uploadDate": {"$gte": date, "$lt": date + timedelta(days=1)}})
    return [{"filename": file['filename'], "uploadDate": file['uploadDate']} for file in files]


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


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/publish', methods=['GET', 'POST'])
def publish():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == '@123admin':
            account = request.form.get('account')
            pdf_file = request.files.get('pdf_file')
            if not pdf_file or not account:
                flash("Please provide all required inputs: account and PDF file.")
                return redirect(url_for('publish'))

            # Define paths for keys and signature
            private_key_path = "private_key.b64"
            public_key_path = "public_key.b64"
            signature_path = "sign.bin"

            # Create a directory to save the uploaded file if it doesn't exist
            upload_dir = "uploads"
            if not os.path.exists(upload_dir):
                os.makedirs(upload_dir)

            # Save the uploaded PDF file
            pdf_path = os.path.join(upload_dir, secure_filename(pdf_file.filename))
            try:
                pdf_file.save(pdf_path)
            except Exception as e:
                flash(f"Failed to save uploaded file: {str(e)}")
                return redirect(url_for('publish'))

            # Generate keys, sign the PDF, and upload to GridFS
            try:
                if generate_keys():
                    print("Keys generated successfully.")
                else:
                    flash("Failed to generate keys.")
                    return redirect(url_for('publish'))

                if sign_pdf(private_key_path, pdf_path, signature_path, account):
                    print(f"PDF signed successfully and saved signature to {signature_path}")
                else:
                    flash("Failed to sign PDF.")
                    return redirect(url_for('publish'))

                if upload_to_gridfs(public_key_path, signature_path, pdf_path, db_name='test'):
                    flash("Uploaded successfully.")
                else:
                    flash("Failed to upload.")
            except Exception as e:
                flash(f"An error occurred during the publishing process: {str(e)}")
                return redirect(url_for('publish'))

            return redirect(url_for('publish'))
        else:
            flash("Bạn không có quyền publish file.")
            return redirect(url_for('publish'))
    
    return render_template('publish.html')

def get_list_of_files():
    files = db.fs.files.find()
    file_list = []
    for file in files:
        file_list.append({"filename": file['filename'], "uploadDate": file['uploadDate']})
    return file_list

from flask import send_file, Response

@app.route('/download', methods=['GET', 'POST'])
def download():
    if request.method == 'POST':
        file_id = request.form.get('file_id')
        try:
            file = db.fs.files.find_one({"_id": ObjectId(file_id), "metadata.signature": {"$exists": True}})
            if not file:
                flash("Signed file not found!")
                return redirect(url_for('download'))
            
            grid_out = fs.get(file['_id'])
            return send_file(grid_out, as_attachment=True, download_name=file['filename'], mimetype='application/pdf')
        
        except Exception as e:
            flash(f"Error: {e}")
            return redirect(url_for('download'))

    # Fetch list of signed files available for download
    signed_files = db.fs.files.find({"metadata.signature": {"$exists": True}})
    return render_template('download.html', files=signed_files)

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        search_type = request.form.get('search_type')
        query = request.form.get('query')

        if search_type == 'name':
            files = find_file_by_name(db, query)
        elif search_type == 'date':
            files = find_file_by_date(db, query)
        else:
            files = []

        return render_template('search.html', files=files)

    return render_template('search.html', files=[])



def select_pdf_file_veri():
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    file_path = filedialog.askopenfilename(title="Select PDF File", filetypes=[("PDF Files", "*.pdf")])
    return file_path

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        # Get the uploaded file
        pdf_file = request.files.get('pdf_file')
        if not pdf_file:
            flash("No file chosen!")
            return redirect(url_for('verify'))

        filename = pdf_file.filename

        # Save the uploaded file to a temporary location
        with tempfile.NamedTemporaryFile(delete=False) as temp_pdf:
            pdf_path = temp_pdf.name
            pdf_file.save(pdf_path)

        public_key_path = "public_key.b64"
        signature_path = "signature.b64"

        # Retrieve the file record from the database
        file_record = db.fs.files.find_one({"filename": filename})
        if not file_record:
            flash(f"File '{filename}' not found in the database.")
            return redirect(url_for('verify'))

        # Extract metadata from the file record
        metadata = file_record.get('metadata', {})
        
        # Retrieve public key and signature from metadata
        public_key_data = metadata.get('public_key', None)
        signature_data = metadata.get('signature', None)
        
        if not public_key_data or not signature_data:
            flash("Public key or signature not found in metadata.")
            return redirect(url_for('verify'))

        # Write public key data to a temporary file
        with open(public_key_path, 'wb') as public_key_file:
            public_key_file.write(public_key_data.encode('utf-8'))
        
        # Write signature data to a temporary file
        with open(signature_path, 'wb') as signature_file:
            signature_file.write(signature_data.encode('utf-8'))

        # Perform signature verification using the temporary files
        if verify_signature(public_key_path, pdf_path, signature_path):
            flash("Signature verified successfully, PDF is safe")
        else:
            flash("Verification failed, PDF may be changed")

        # Clean up the temporary PDF file
        os.remove(pdf_path)

        return redirect(url_for('verify'))

    return render_template('verify.html')

if __name__ == '__main__':
    app.run(debug=True)
