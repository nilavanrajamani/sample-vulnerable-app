# HIGHLY VULNERABLE PAYMENT PROCESSOR
# This module contains multiple PCI DSS violations for demonstration purposes

import sqlite3
import json
import base64
from flask import Flask, request, render_template_string

# VIOLATION 1 & 2: Hardcoded database credentials (Rule 8.6.1)
DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWORD = "admin123"  # Hardcoded password!
DB_NAME = "payment_db"

# VIOLATION 3: Hardcoded API keys (Rule 8.6.1)
STRIPE_API_KEY = "sk_live_DEMONSTRATION_KEY_NOT_REAL"
MERCHANT_ID = "merchant_demo_key"

# VIOLATION 4: Weak encryption key stored in code (Rule 3.4, 3.5.1)
ENCRYPTION_KEY = "weak_key_1234"
ENCRYPTION_IV = "init_vector_5678"

app = Flask(__name__)

# VIOLATION 5: Storing sensitive data in cookies without encryption (Rule 3.3, 4.1)
@app.route('/process_payment', methods=['POST'])
def process_payment():
    """
    VIOLATION: No input validation - susceptible to SQL injection (Rule 6.5.1)
    VIOLATION: Stores PAN and CVV in plaintext (Rule 3.3.1, 3.3.2)
    """
    card_number = request.form.get('card_number')  # No validation!
    cvv = request.form.get('cvv')  # No validation!
    expiry = request.form.get('expiry')
    amount = request.form.get('amount')
    
    # VIOLATION 6: SQL Injection - directly interpolating user input
    query = f"INSERT INTO payments (card_number, cvv, expiry, amount) VALUES ('{card_number}', '{cvv}', '{expiry}', '{amount}')"
    
    try:
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        cursor.execute(query)  # Raw SQL execution!
        conn.commit()
    except Exception as e:
        # VIOLATION 7: Exposing sensitive error details to users (Rule 10.2)
        return json.dumps({"error": str(e), "query": query}), 500
    
    # VIOLATION 8: Storing sensitive data in cookies (Rule 3.3, 4.1)
    response = {
        "status": "success",
        "card_number": card_number,  # Returning card number in response!
        "cvv": cvv,  # Returning CVV in response!
        "transaction_id": "TXN_12345"
    }
    
    # VIOLATION 9: Cookie set without secure flag or httponly (Rule 4.1)
    # Storing PAN in a cookie in plaintext
    return json.dumps(response)

@app.route('/refund', methods=['POST'])
def refund_payment():
    """
    VIOLATION: No authentication/authorization (Rule 7.1)
    VIOLATION: No input validation (Rule 6.5.1)
    """
    transaction_id = request.form.get('transaction_id')
    
    # VIOLATION 10: No authorization check - anyone can refund any transaction!
    # VIOLATION 11: SQL Injection vulnerability
    query = f"DELETE FROM payments WHERE transaction_id = '{transaction_id}'"
    
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
    
    # VIOLATION 12: No audit logging (Rule 10.3)
    return json.dumps({"status": "refunded"}), 200

@app.route('/export_data', methods=['GET'])
def export_customer_data():
    """
    VIOLATION: No authentication/authorization (Rule 7.1)
    VIOLATION: Exposing sensitive customer data (Rule 3.3)
    VIOLATION: Unencrypted data transmission (Rule 4.1)
    VIOLATION: No audit logging (Rule 10.3)
    """
    # VIOLATION: No authentication check!
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM customers")  # Fetch all customers!
    
    customers = cursor.fetchall()
    
    # VIOLATION: Returning data in plaintext over HTTP
    return json.dumps({
        "customers": customers,
        "count": len(customers)
    }), 200

@app.route('/weak_password_reset', methods=['POST'])
def reset_password():
    """
    VIOLATION: Weak password storage (Rule 8.5.1)
    VIOLATION: No rate limiting (Rule 6.5.10)
    VIOLATION: No account lockout (Rule 8.1.7)
    """
    username = request.form.get('username')
    new_password = request.form.get('new_password')
    
    # VIOLATION: Storing password as plaintext base64 (not real encryption)
    encoded_password = base64.b64encode(new_password.encode()).decode()
    
    # VIOLATION: No password complexity validation
    query = f"UPDATE users SET password = '{encoded_password}' WHERE username = '{username}'"
    
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(query)  # SQL injection!
    conn.commit()
    
    return json.dumps({"status": "password_reset_success"}), 200

@app.route('/get_card_details', methods=['GET'])
def get_card_details():
    """
    VIOLATION: Exposing PAN data (Rule 3.3.1)
    VIOLATION: No access controls (Rule 7.1)
    VIOLATION: Unencrypted transmission (Rule 4.1)
    VIOLATION: No audit logging (Rule 10.3)
    """
    card_id = request.args.get('card_id')
    
    # VIOLATION: No authentication/authorization
    # VIOLATION: SQL Injection
    query = f"SELECT card_number, cvv, expiry FROM cards WHERE id = {card_id}"
    
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(query)
    result = cursor.fetchone()
    
    # VIOLATION: Returning sensitive card data in plaintext
    return json.dumps({
        "card_number": result[0] if result else None,
        "cvv": result[1] if result else None,
        "expiry": result[2] if result else None
    }), 200

@app.route('/admin_panel', methods=['GET'])
def admin_panel():
    """
    VIOLATION: Hardcoded admin credentials (Rule 8.6.1)
    VIOLATION: No access controls (Rule 7.1)
    VIOLATION: No multi-factor authentication (Rule 8.3)
    """
    admin_username = "admin"
    admin_password = "SuperSecurePassword123!"  # Hardcoded!
    
    # VIOLATION: Credentials sent as GET parameter
    username = request.args.get('username')
    password = request.args.get('password')
    
    # VIOLATION: Basic string comparison for authentication
    if username == admin_username and password == admin_password:
        return render_template_string("""
            <h1>Admin Panel</h1>
            <p>Welcome Admin! All customer data is here.</p>
            <!-- VIOLATION: Sensitive data embedded in HTML -->
            <a href="/admin/dump_database">Export All Data</a>
        """), 200
    
    return "Unauthorized", 401

def log_transaction(transaction_data):
    """
    VIOLATION: Insufficient logging (Rule 10.3)
    VIOLATION: Storing logs in plaintext (Rule 10.4)
    VIOLATION: No log protection (Rule 10.4.1)
    """
    # VIOLATION: Logging sensitive information like PAN and CVV
    log_entry = f"Transaction: {transaction_data} - Timestamp: {__import__('datetime').datetime.now()}"
    
    # VIOLATION: Writing logs to unprotected file
    with open('/tmp/payment_logs.txt', 'a') as log_file:
        log_file.write(log_entry + '\n')  # Plaintext logs with sensitive data!

@app.route('/payment_api', methods=['POST'])
def payment_api():
    """
    VIOLATION: No rate limiting (Rule 6.5.10)
    VIOLATION: No input validation (Rule 6.5.1)
    VIOLATION: SQL Injection (Rule 6.5.1)
    """
    data = request.get_json()
    
    # VIOLATION: No validation of input data
    card_num = data.get('card_number')
    cvv_code = data.get('cvv')
    
    # VIOLATION: Directly using user input in SQL query
    query = f"SELECT * FROM fraud_check WHERE pan = '{card_num}' AND cvv = '{cvv_code}'"
    
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    try:
        cursor.execute(query)  # SQL Injection vulnerable!
        results = cursor.fetchall()
        
        # VIOLATION: Returning data with no encryption (Rule 4.1)
        return json.dumps({"status": "ok", "results": results}), 200
    except Exception as e:
        # VIOLATION: Exposing database errors to client (Rule 10.2)
        return json.dumps({"error": str(e), "query": query}), 500

if __name__ == '__main__':
    # VIOLATION: Running Flask in debug mode with secrets in code (Rule 6.5.10)
    app.run(debug=True, host='0.0.0.0', port=5000)
