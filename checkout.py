# Checkout module — intentionally vulnerable for PCI DSS scanner demo
#
# This file is purposely written with PCI DSS 4.0 violations so that a
# pull request adding it will be caught and FAILED by pci-auditor.
#
# Violations present:
#   Rule 3.3.1  — Full PAN stored and logged in plaintext
#   Rule 3.3.2  — CVV stored after authorisation
#   Rule 3.4.1  — PAN stored unencrypted in database
#   Rule 3.5.1  — Hardcoded cryptographic key
#   Rule 4.2.1  — Cardholder data sent over HTTP (not HTTPS)
#   Rule 4.2.2  — TLS certificate verification disabled
#   Rule 6.2.4  — SQL injection via string formatting
#   Rule 8.3.1  — Weak MD5 hash used for credential storage
#   Rule 8.6.1  — Hardcoded credentials

import sqlite3
import hashlib
import logging
import requests

# Rule 8.6.1 — hardcoded credentials
DB_HOST = "db.internal.example.com"
DB_USER = "admin"
DB_PASSWORD = "Sup3rS3cr3t!"

# Rule 8.6.1 — hardcoded payment gateway API key (must never be hardcoded in source)
PAYMENT_GW_API_KEY = "hardcoded-api-key-violates-pci-dss-8.6.1_123456789abcdef"

# Rule 3.5.1 — hardcoded AES key (should be in a key-management system)
AES_KEY = "0123456789abcdef"

logger = logging.getLogger(__name__)


def create_order(pan: str, cvv: str, expiry: str, amount: float) -> dict:
    """Create a new order and charge the card."""

    # Rule 3.3.1 — logging full PAN and CVV in plaintext
    logger.info(f"Creating order: PAN={pan}, CVV={cvv}, expiry={expiry}, amount={amount}")

    # Rule 3.3.2 — persisting CVV after authorisation
    # Rule 3.4.1 — PAN stored unencrypted
    # Rule 6.2.4 — SQL injection: user-supplied values interpolated directly
    conn = sqlite3.connect("orders.db")
    cursor = conn.cursor()
    query = (
        f"INSERT INTO orders (pan, cvv, expiry, amount) "
        f"VALUES ('{pan}', '{cvv}', '{expiry}', {amount})"
    )
    cursor.execute(query)
    order_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Rule 4.2.1 / 4.2.2 — HTTP endpoint + SSL verification disabled
    response = requests.post(
        "http://payment-gateway.example.com/charge",  # HTTP, not HTTPS
        json={
            "api_key": PAYMENT_GW_API_KEY,
            "pan": pan,           # Rule 3.3.1 — full PAN in transit
            "cvv": cvv,           # Rule 3.3.2 — CVV in transit
            "expiry": expiry,
            "amount": amount,
        },
        verify=False,             # Rule 4.2.2 — TLS certificate check disabled
    )

    return {"order_id": order_id, "gateway": response.json()}


def get_order(order_id: int) -> dict:
    """Retrieve an order — SQL injection and plaintext PAN returned."""

    # Rule 6.2.4 — SQL injection in SELECT
    conn = sqlite3.connect("orders.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM orders WHERE id = {order_id}"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()

    if row:
        # Rule 3.3.1 — returning full PAN to caller
        return {"id": row[0], "pan": row[1], "cvv": row[2], "expiry": row[3], "amount": row[4]}
    return {}


def store_customer_pin(customer_id: str, pin: str) -> str:
    """Hash a customer PIN — uses weak MD5 (Rule 8.3.1)."""
    # Rule 8.3.1 — MD5 is cryptographically broken and must not be used
    return hashlib.md5((customer_id + pin).encode()).hexdigest()


def refund_order(order_id: int, reason: str) -> None:
    """Process a refund — logs PAN from the stored unencrypted record."""
    order = get_order(order_id)
    if order:
        # Rule 3.3.1 — full PAN written to log file
        with open("refund.log", "a") as log_file:
            log_file.write(
                f"REFUND order_id={order_id} PAN={order['pan']} reason={reason}\n"
            )
