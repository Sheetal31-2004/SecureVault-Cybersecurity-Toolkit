# crypto_utils.py
import os
import time
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

KEY_FILE = "secret.key"

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)

def load_key():
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()

def encrypt_message(message, key):

    start_time = time.perf_counter()

    encrypted = Fernet(key).encrypt(
        message.encode()
    )

    end_time = time.perf_counter()

    return {

        "ciphertext": encrypted.decode(),

        "algorithm": "AES-256 (Fernet)",

        "key_size": "256-bit",

        "library": "Cryptography - Fernet",

        "mode": "Symmetric Encryption",

        "security": "HIGH",

        "original_size": len(message.encode()),

        "encrypted_size": len(encrypted),

        "time_taken": round(
            end_time - start_time,
            6
        ),

        "timestamp": datetime.now().strftime(
            "%d-%m-%Y %I:%M:%S %p"
        )

    }

def decrypt_message(token, key):
    f = Fernet(key)
    return f.decrypt(token).decode()


def encrypt_file(filepath, key):

    fernet = Fernet(key)

    with open(filepath, "rb") as file:
        data = file.read()

    encrypted = fernet.encrypt(data)

    encrypted_path = filepath + ".enc"

    with open(encrypted_path, "wb") as file:
        file.write(encrypted)

    return encrypted_path

# ==========================================================
# GENERATE RSA KEY PAIR
# ==========================================================

def generate_keys():

    private_key = rsa.generate_private_key(

        public_exponent=65537,

        key_size=2048

    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(

        encoding=serialization.Encoding.PEM,

        format=serialization.PrivateFormat.PKCS8,

        encryption_algorithm=serialization.NoEncryption()

    )

    public_pem = public_key.public_bytes(

        encoding=serialization.Encoding.PEM,

        format=serialization.PublicFormat.SubjectPublicKeyInfo

    )

    return private_pem, public_pem

# ==========================================================
# SIGN FILE
# ==========================================================

def sign_file(file_path):

    private_key, public_key = generate_keys()

    private = serialization.load_pem_private_key(

        private_key,

        password=None

    )

    with open(file_path, "rb") as f:

        data = f.read()

    signature = private.sign(

        data,

        padding.PSS(

            mgf=padding.MGF1(hashes.SHA256()),

            salt_length=padding.PSS.MAX_LENGTH

        ),

        hashes.SHA256()

    )

    return {

        "signature": signature,

        "private_key": private_key,

        "public_key": public_key

    }

# ==========================================================
# VERIFY SIGNATURE
# ==========================================================

def verify_signature(

    file_path,

    signature,

    public_key

):

    public = serialization.load_pem_public_key(

        public_key

    )

    with open(file_path, "rb") as f:

        data = f.read()

    try:

        public.verify(

            signature,

            data,

            padding.PSS(

                mgf=padding.MGF1(hashes.SHA256()),

                salt_length=padding.PSS.MAX_LENGTH

            ),

            hashes.SHA256()

        )

        return True

    except InvalidSignature:

        return False



