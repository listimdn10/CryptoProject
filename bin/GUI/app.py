import subprocess
import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from pymongo import MongoClient
import gridfs
import qrcode
from datetime import datetime
from io import BytesIO
from bson import ObjectId
from PyPDF2 import PdfWriter, PdfReader
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
from werkzeug.utils import secure_filename
import base64
import pprint
from datetime import datetime, timedelta  # Importing timedelta
import logging


app = Flask(__name__)
app.secret_key = 'supersecretkey'



# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client['crypto_db']
fs = gridfs.GridFS(db)

pathOpenssl = r'D:\\MMH\\CRYPTO_PROJECGT\\CryptoProject\\Openssl321-VS\\bin\\GUI\\bin\\openssl.exe'
cert_file = r'D:\\MMH\\CRYPTO_PROJECGT\\CryptoProject\\Openssl321-VS\\bin\\GUI\\dilithium3_srv.crt'
pubkey_file = r'D:\\MMH\\CRYPTO_PROJECGT\\CryptoProject\\Openssl321-VS\\bin\\GUI\\dilithium3_srv.pubkey'

def generate_ca_key_and_self_signed_certificate(ca_name, ca_country, ca_state, ca_locality, ca_org, ca_org_unit, ca_email):
    try:
        command = f'{pathOpenssl} req -x509 -new -newkey dilithium3 -keyout root_CA.key -out root_CA.crt -nodes -subj "/CN={ca_name}/C={ca_country}/ST={ca_state}/L={ca_locality}/O={ca_org}/OU={ca_org_unit}/emailAddress={ca_email}" -days 365 -provider oqsprovider -config "C:\\Program Files\\Common Files\\SSL\\openssl.cnf"'
        subprocess.run(command, shell=True, check=True)
        print("CA key and self-signed certificate generated successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error generating CA key and self-signed certificate: {e}")

def generate_server_key_and_certificate(server_name, server_country, server_state, server_locality, server_org, server_org_unit, server_email):
    try:
        genkey_command = f'{pathOpenssl} genpkey -algorithm dilithium3 -out dilithium3_srv.key -provider oqsprovider'
        subprocess.run(genkey_command, shell=True, check=True)
        logging.info("Server key generated successfully.")

        if not os.path.exists("dilithium3_srv.key"):
            raise FileNotFoundError("Server key file not found.")

        req_command = f'{pathOpenssl} req -new -key dilithium3_srv.key -out dilithium3_srv.csr -nodes -subj "/CN={server_name}/C={server_country}/ST={server_state}/L={server_locality}/O={server_org}/OU={server_org_unit}/emailAddress={server_email}" -provider oqsprovider -config "C:\\Program Files\\Common Files\\SSL\\openssl.cnf"'
        subprocess.run(req_command, shell=True, check=True)
        logging.info("CSR generated successfully.")

        if not os.path.exists("dilithium3_srv.csr"):
            raise FileNotFoundError("CSR file not found.")

        sign_command = f'{pathOpenssl} x509 -req -in dilithium3_srv.csr -out dilithium3_srv.crt -CA root_CA.crt -CAkey root_CA.key -CAcreateserial -days 365 -provider oqsprovider'
        subprocess.run(sign_command, shell=True, check=True)
        logging.info("Certificate generated successfully.")

        if not os.path.exists("dilithium3_srv.crt"):
            raise FileNotFoundError("Certificate file not found.")
        
        detachPubKeyFromCert(cert_file, pubkey_file)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error generating server key and certificate: {e.stderr}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        raise


def detachPubKeyFromCert(cert_file, public_key_file):
    try:
        command = f"{pathOpenssl} x509 -in {cert_file} -pubkey -noout -out {public_key_file}"
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        logging.info(f"Output: {result.stdout}")
        logging.info("Public key extracted successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error extracting public key: {e.stderr}")
        raise

# Function to sign data
def signData(privateKey, dataFile, signatureFile):
    command = f'{pathOpenssl} dgst -sha256 -sign "{privateKey}" -out "{signatureFile}" "{dataFile}"'
    result = subprocess.run(command, shell=True)
    return result.returncode == 0

# Function to verify signature
def verifySignature(public_key_file, data_file, signature_base64):
    signature = base64.b64decode(signature_base64.encode("utf-8"))
    with open("temp_signature.bin", "wb") as sig_file:
        sig_file.write(signature)
    command = f'{pathOpenssl} dgst -sha256 -verify "{public_key_file}" -signature "temp_signature.bin" "{data_file}"'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    os.remove("temp_signature.bin")
    return "Verified OK" in result.stdout

# Function to create QR watermark
def makeWatermark(account):
    watermarkName = "qr.pdf"
    doc = canvas.Canvas(watermarkName)
    qr = qrcode.QRCode(version=2, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=4)
    now = datetime.now()
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

def upload_to_gridfs(filepath, public_key, signature):
    filename = os.path.basename(filepath)
    with open(filepath, "rb") as f:
        file_data = f.read()
    metadata = {
        "author": "admin",
        "public_key": public_key,
        "signature": signature
    }
    fs.put(file_data, filename=filename, metadata=metadata)

# Function to find file by name
def find_file_by_name(db, partial_filename):
    regex_pattern = f".*{partial_filename}.*"
    files = db.fs.files.find({"filename": {"$regex": regex_pattern}})
    result_files = []
    if files:
        for file in files:
            result_files.append({
                "filename": file['filename'],
                "uploadDate": file['uploadDate']
            })
    return result_files

# Function to find file by date
def find_file_by_date(db, date_str):
    date = datetime.strptime(date_str, "%Y-%m-%d")
    files = db.fs.files.find({"uploadDate": {"$gte": date, "$lt": date + timedelta(days=1)}})
    result_files = []
    if files:
        for file in files:
            result_files.append({
                "filename": file['filename'],
                "uploadDate": file['uploadDate']
            })
    return result_files

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/generate_ca_certificate', methods=['GET', 'POST'])
def generate_ca_certificate():
    if request.method == 'POST':
        ca_name = request.form['ca_name']
        ca_country = request.form['ca_country']
        ca_state = request.form['ca_state']
        ca_locality = request.form['ca_locality']
        ca_org = request.form['ca_org']
        ca_org_unit = request.form['ca_org_unit']
        ca_email = request.form['ca_email']
        try:
            generate_ca_key_and_self_signed_certificate(ca_name, ca_country, ca_state, ca_locality, ca_org, ca_org_unit, ca_email)
            flash("CA key and self-signed certificate generated successfully.")
        except Exception as e:
            flash(f"Failed to generate CA key and certificate: {str(e)}")
        return redirect(url_for('generate_ca_certificate'))
    return render_template('generate_ca_certificate.html')

@app.route('/generate_server_certificate', methods=['GET', 'POST'])
def generate_server_certificate():
    if request.method == 'POST':
        server_name = request.form['server_name']
        server_country = request.form['server_country']
        server_state = request.form['server_state']
        server_locality = request.form['server_locality']
        server_org = request.form['server_org']
        server_org_unit = request.form['server_org_unit']
        server_email = request.form['server_email']
        try:
            generate_server_key_and_certificate(server_name, server_country, server_state, server_locality, server_org, server_org_unit, server_email)
            detachPubKeyFromCert(cert_file, pubkey_file)

            # Upload the server certificate to the database
            with open(cert_file, "rb") as cert_file_obj:
                cert_data = cert_file_obj.read()

            metadata = {
                "type": "server_certificate",
                "upload_date": datetime.now(),
            }
            fs.put(cert_data, filename="server_certificate.crt", metadata=metadata)

            flash("Server key and certificate generated and uploaded successfully.")
        except Exception as e:
            flash(f"Failed to generate server key and certificate: {str(e)}")
        return redirect(url_for('generate_server_certificate'))
    return render_template('generate_server_certificate.html')



@app.route('/publish', methods=['GET', 'POST'])
def publish():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == '@123admin':
            account = request.form.get('account')
            pdf_file = request.files.get('pdf_file')
            if not account or not pdf_file:
                flash("Please provide all required inputs: account and PDF file.")
                return redirect(url_for('publish'))
            
            try:
                generate_ca_key_and_self_signed_certificate()
                generate_server_key_and_certificate()
                detachPubKeyFromCert(cert_file, pubkey_file)
            except Exception as e:
                flash(f"Failed to generate keys and certificates: {str(e)}")
                return redirect(url_for('publish'))

            private_key = "dilithium3_srv.key"
            signature_file = "signature"

            upload_dir = "uploads"
            if not os.path.exists(upload_dir):
                os.makedirs(upload_dir)

            pdf_path = os.path.join(upload_dir, secure_filename(pdf_file.filename))
            pdf_file.save(pdf_path)

            try:
                watermark = makeWatermark(account)
                signed_pdf = makePdf(pdf_path, watermark)
                
                if signData(private_key, signed_pdf, signature_file):
                    with open(signature_file, "rb") as sig_file:
                        signature = base64.b64encode(sig_file.read()).decode("utf-8")
                    with open(pubkey_file, "r") as pubkey_file_obj:
                        public_key = pubkey_file_obj.read()
                    upload_to_gridfs(signed_pdf, public_key, signature)
                    flash(f"PDF signed and uploaded successfully as: {signed_pdf}")
                else:
                    flash("Failed to sign PDF.")
            except Exception as e:
                flash(f"Error during PDF processing: {str(e)}")
        else:
            flash("You do not have permission to publish!")
        return redirect(url_for('publish'))
    return render_template('publish.html')

@app.route('/download', methods=['GET', 'POST'])
def download():
    if request.method == 'POST':
        file_id = request.form.get('file_id')
        try:
            file = fs.find_one({"_id": ObjectId(file_id), "metadata.author": "admin"})
            if not file:
                flash("Signed file not found!")
                return redirect(url_for('download'))
            grid_out = fs.get(file['_id'])
            return send_file(grid_out, as_attachment=True, download_name=file.filename)
        except Exception as e:
            flash(f"Failed to download file: {str(e)}")
    return render_template('download.html')

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        search_type = request.form.get('search_type')
        search_value = request.form.get('search_value')
        try:
            if search_type == 'name':
                files = find_file_by_name(db, search_value)
            elif search_type == 'date':
                files = find_file_by_date(db, search_value)
            else:
                files = []
            return render_template('search_results.html', files=files)
        except Exception as e:
            flash(f"Search error: {str(e)}")
    return render_template('search.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        file_id = request.form.get('file_id')
        try:
            file = fs.find_one({"_id": ObjectId(file_id)})
            if not file:
                flash("File not found in database.")
                return redirect(url_for('verify'))
            
            metadata = file.metadata
            if not metadata:
                flash("No metadata found for the file.")
                return redirect(url_for('verify'))

            public_key = metadata.get("public_key")
            signature_base64 = metadata.get("signature")
            if not public_key or not signature_base64:
                flash("Public key or signature not found in metadata.")
                return redirect(url_for('verify'))

            with open("temp_public_key.pub", "w") as pub_file:
                pub_file.write(public_key)
            file_path = os.path.join("uploads", file.filename)
            with open(file_path, "wb") as f:
                f.write(file.read())

            if verifySignature("temp_public_key.pub", file_path, signature_base64):
                flash("Signature verified successfully.")
            else:
                flash("Signature verification failed.")
            os.remove("temp_public_key.pub")
        except Exception as e:
            flash(f"Verification error: {str(e)}")
    return render_template('verify.html')

if __name__ == '__main__':
    app.run(debug=True)
