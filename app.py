# Sample Vulnerable Payment Application
# This is a demo app with multiple PCI DSS violations for testing pci-auditor

import os
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

# Hardcoded database password (Rule 8.6.1)
DB_PASSWORD = "hunter2"

# Hardcoded API key (Rule 8.6.1)
STRIPE_API_KEY = "your_stripe_test_key_here"

# Hardcoded PAN (Rule 3.3.1)
TEST_PAN = "4111111111111111"

# Hardcoded CVV (Rule 3.3.2)
TEST_CVV = "123"

@app.route('/process_payment', methods=['POST'])
def process_payment():
    data = request.json

    # Storing PAN in memory (Rule 3.3.1)
    pan = data.get('card_number', TEST_PAN)
    cvv = data.get('cvv', TEST_CVV)

    # Logging sensitive data (Rule 3.3.1)
    print(f"Processing payment for PAN: {pan}, CVV: {cvv}")

    # Insecure HTTP endpoint (Rule 4.2.1)
    # No HTTPS enforcement

    # SQL injection vulnerability (Rule 6.2.4)
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    query = f"INSERT INTO payments (pan, cvv) VALUES ('{pan}', '{cvv}')"
    cursor.execute(query)
    conn.commit()
    conn.close()

    return jsonify({"status": "success", "message": "Payment processed"})

@app.route('/get_payment/<payment_id>')
def get_payment(payment_id):
    # SQL injection in SELECT (Rule 6.2.4)
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM payments WHERE id = {payment_id}"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()

    if result:
        # Returning sensitive data (Rule 3.3.1)
        return jsonify({"pan": result[1], "cvv": result[2]})
    return jsonify({"error": "Payment not found"})

if __name__ == '__main__':
    # Running on HTTP (Rule 4.2.1)
    app.run(host='0.0.0.0', port=5000, debug=True)