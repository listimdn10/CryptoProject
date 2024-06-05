import hashlib
import ctypes
import sys
import os
import base64

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

def sign_pdf(private_key_path, pdf_path, signature_path):
    priv_key_data = read_from_file(private_key_path)
    with open(pdf_path, 'rb') as f:
        pdf_data = f.read()
    hashed_pdf_data = hash_data(pdf_data)
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
        print("Verification failed")
        return False
    print("Signature verified successfully")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} [genkeys|sign|verify] [other parameters]")
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "genkeys":
        if generate_keys():
            print("Keys generated successfully.")
        else:
            print("Failed to generate keys.")
    elif mode == "sign":
        if len(sys.argv) != 5:
            print(f"Usage: {sys.argv[0]} sign <private key file> <PDF file> <signature output file>")
            sys.exit(1)
        private_key_path = sys.argv[2]
        pdf_path = sys.argv[3]
        signature_path = sys.argv[4]
        if sign_pdf(private_key_path, pdf_path, signature_path):
            print(f"PDF signed successfully and saved signature to {signature_path}")
        else:
            print("Failed to sign PDF.")
    elif mode == "verify":
        if len(sys.argv) != 5:
            print(f"Usage: {sys.argv[0]} verify <public key file> <PDF file> <signature file>")
            sys.exit(1)
        public_key_path = sys.argv[2]
        pdf_path = sys.argv[3]
        signature_path = sys.argv[4]
        if verify_signature(public_key_path, pdf_path, signature_path):
            print("PDF verified successfully.")
        else:
            print("Failed to verify PDF.")
    else:
        print("Invalid mode! Please choose genkeys, sign, or verify!")
        sys.exit(1)

    sys.exit(0)
