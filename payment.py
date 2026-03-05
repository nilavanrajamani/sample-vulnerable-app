# Payment processing module

import requests
import json

def process_stripe_payment(amount, card_number, cvv, expiry):
    # Using HTTP instead of HTTPS (Rule 4.2.1)
    url = "http://api.stripe.com/v1/charges"

    # Sending sensitive data over HTTP
    data = {
        "amount": amount,
        "currency": "usd",
        "source": {
            "number": card_number,  # PAN in request
            "exp_month": expiry.split('/')[0],
            "exp_year": "20" + expiry.split('/')[1],
            "cvc": cvv  # CVV in request
        }
    }

    headers = {
        "Authorization": f"Bearer {__import__('config').STRIPE_SECRET_KEY}",
        "Content-Type": "application/json"
    }

    # No SSL verification (Rule 4.2.2)
    response = requests.post(url, json=data, headers=headers, verify=False)

    return response.json()

def validate_card(card_number):
    # Basic Luhn check, but storing card temporarily
    temp_storage = card_number  # Temporary storage of PAN (Rule 3.3.1)

    # Simple validation
    if len(card_number) < 13 or len(card_number) > 19:
        return False

    # Luhn algorithm
    digits = [int(d) for d in str(card_number)]
    for i in range(len(digits) - 2, -1, -2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9

    return sum(digits) % 10 == 0

def mask_pan(pan):
    # Incorrect masking - shows too many digits (Rule 3.6.1)
    if len(pan) <= 4:
        return pan
    return pan[:-4] + "****"  # Shows last 4, but PCI requires different masking

def log_transaction(pan, amount):
    # Logging PAN in logs (Rule 3.3.1)
    print(f"Transaction: PAN ending in {pan[-4:]} for ${amount}")
    # But actually logging full PAN
    with open('transaction.log', 'a') as f:
        f.write(f"PAN: {pan}, Amount: {amount}\n")

# XSS vulnerability (Rule 6.2.4)
def generate_receipt_html(pan, amount):
    masked_pan = mask_pan(pan)
    html = f"""
    <html>
    <body>
        <h1>Receipt</h1>
        <p>Card: {masked_pan}</p>
        <p>Amount: ${amount}</p>
        <script>alert('XSS: {pan}')</script>  <!-- XSS vulnerability -->
    </body>
    </html>
    """
    return html