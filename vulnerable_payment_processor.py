# HIGHLY VULNERABLE PAYMENT PROCESSOR
# This module contains PCI DSS violations for demonstration purposes

import sqlite3
import json
from flask import Flask, request

DB_PASSWORD = "admin123"
STRIPE_API_KEY = "sk_live_DEMONSTRATION_KEY_NOT_REAL"

app = Flask(__name__)

@app.route('/process_payment', methods=['POST'])
def process_payment():
    card_number = request.form.get('card_number')
    cvv = request.form.get('cvv')
    expiry = request.form.get('expiry')
    amount = request.form.get('amount')

    query = f"INSERT INTO payments (card_number, cvv, expiry, amount) VALUES ('{card_number}', '{cvv}', '{expiry}', '{amount}')"

    try:
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
    except Exception as e:
        return json.dumps({"error": str(e), "query": query}), 500

    return json.dumps({
        "status": "success",
        "card_number": card_number,
        "cvv": cvv,
        "transaction_id": "TXN_12345"
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
