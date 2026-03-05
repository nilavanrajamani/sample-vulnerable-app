# Utility functions with security issues

import os
import subprocess

def backup_database():
    # Command injection vulnerability (Rule 6.2.4)
    db_name = "payments.db"
    backup_cmd = f"cp {db_name} {db_name}.backup"
    subprocess.run(backup_cmd, shell=True)  # Shell injection risk

def send_email_notification(email, message):
    # No input validation, potential command injection
    cmd = f"mail -s 'Notification' {email} <<< '{message}'"
    os.system(cmd)

def encrypt_data(data):
    # Using deprecated DES (Rule 12.3.3)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    key = b"12345678"  # 8-byte key for DES
    iv = b"12345678"  # 8-byte IV

    cipher = Cipher(algorithms.DES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + b"\0" * (8 - len(data) % 8)  # Simple padding
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_data(encrypted_data):
    # Same deprecated crypto
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    key = b"12345678"
    iv = b"12345678"

    cipher = Cipher(algorithms.DES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# Hardcoded credentials in environment (but actually in code)
def get_db_credentials():
    return {
        "host": "localhost",
        "user": "root",
        "password": os.getenv("DB_PASS", "defaultpass123")  # Fallback to hardcoded
    }

# File upload without validation (potential security issue)
def save_uploaded_file(file_content, filename):
    with open(f"uploads/{filename}", "wb") as f:
        f.write(file_content)  # No validation, could be malicious

# Session management issue
sessions = {}  # In-memory sessions, no expiration

def create_session(user_id, pan):
    session_id = str(hash(user_id + pan))  # Weak session ID generation
    sessions[session_id] = {"user_id": user_id, "pan": pan}  # Storing PAN in session
    return session_id

def get_session(session_id):
    return sessions.get(session_id, {})

# CSRF protection missing (Rule 6.4.1)
def process_form_submission(form_data):
    # No CSRF token check
    pan = form_data.get("card_number")
    # Process payment without CSRF validation
    return {"status": "processed", "pan": pan}