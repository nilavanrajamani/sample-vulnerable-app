# Database module with PCI violations

import sqlite3
import logging

# Hardcoded encryption key (Rule 3.5.1)
ENCRYPTION_KEY = "mysecretkey12345"

def init_db():
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    # Storing PAN without encryption (Rule 3.4.1)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY,
            pan TEXT,  -- Primary Account Number stored in plain text
            cvv TEXT,  -- CVV stored
            expiry TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_payment(pan, cvv, expiry):
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()

    # No encryption before storage (Rule 3.4.1)
    cursor.execute("INSERT INTO payments (pan, cvv, expiry) VALUES (?, ?, ?)", (pan, cvv, expiry))

    # Logging sensitive data (Rule 3.3.1)
    logging.info(f"Saved payment: PAN={pan}, CVV={cvv}")

    conn.commit()
    conn.close()

def get_all_payments():
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM payments")
    results = cursor.fetchall()
    conn.close()

    # Returning all sensitive data (Rule 3.3.1)
    return results

# MD5 hash for password (Rule 8.3.1)
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Telnet connection (Rule 2.2.7)
import telnetlib
def connect_to_legacy_system():
    tn = telnetlib.Telnet('legacy.example.com', 23)
    tn.write(b"admin\n")
    tn.write(b"password123\n")  # Hardcoded password
    return tn