"""
Demo: Layer 1 — Regex / Pattern Detection
==========================================
These violations are caught purely by keyword and regex pattern matching.
No AI is needed — every finding is produced by a code_indicator rule.

Scan command (pattern-only):
  pci-auditor scan pr --repo-path . --base-branch origin/main --no-ai

Expected: All violations found with source=pattern

Rules triggered by regex in this file
--------------------------------------
Rule 3.3.1  CRITICAL  — PAN literal + 'cvv' / 'card_number' / 'pan' keyword
Rule 8.6.2  CRITICAL  — password / api_key / DB_PASSWORD hardcoded
Rule 4.2.1  CRITICAL  — http:// endpoint literal
Rule 8.6.1  HIGH      — hashlib.md5 / hashlib.sha1
Rule 12.3.3 HIGH      — 3DES / RC4 named in import or string
Rule 4.2.1.1 MEDIUM   — verify=False in request call
Rule 8.3.6  HIGH      — MIN_PASSWORD_LENGTH < 12
Rule 6.2.4  HIGH      — execute("..." + user_input) SQL injection / eval()
"""

import hashlib
import requests
import sqlite3

# ── Rule 3.3.1 (Critical) ─────────────────────────────────────────────────────
# Regex hits: 16-digit sequence, keywords 'pan', 'cvv', 'card_number'

PRIMARY_ACCOUNT_NUMBER = "4111111111111111"      # literal PAN stored in source
card_number = "5500005555555559"                  # Mastercard test PAN
cvv = "737"                                       # SAD: CVV security code

# ── Rule 8.6.2 (Critical) ─────────────────────────────────────────────────────
# Regex hits: password = '...', api_key = '...', DB_PASSWORD = '...'

password = "Sup3rS3cret!"
api_key  = "sk-1234567890abcdef1234567890abcdef"
DB_PASSWORD = "postgres_admin_2024"

# ── Rule 4.2.1 (Critical) ─────────────────────────────────────────────────────
# Regex hits: literal 'http://' URLs

PAYMENT_GATEWAY_URL = "http://payments.example.com/charge"
CARD_VAULT_URL      = "http://vault.internal/tokenise"

# ── Rule 8.6.1 (High) ─────────────────────────────────────────────────────────
# Regex hits: hashlib.md5, hashlib.sha1


def hash_password_md5(raw: str) -> str:
    return hashlib.md5(raw.encode()).hexdigest()        # MD5 — broken


def hash_password_sha1(raw: str) -> str:
    return hashlib.sha1(raw.encode()).hexdigest()       # SHA-1 — broken


# ── Rule 12.3.3 (High) ────────────────────────────────────────────────────────
# Regex hits: 'RC4', '3DES', 'ARC4' in import statement and string literal

from Crypto.Cipher import DES3, ARC4                   # weak cipher imports
CIPHER_SUITE = "RC4-SHA"                               # RC4 cipher suite configured

# ── Rule 4.2.1.1 (Medium) ─────────────────────────────────────────────────────
# Regex hit: verify=False


def post_payment(payload: dict) -> requests.Response:
    return requests.post(PAYMENT_GATEWAY_URL, json=payload, verify=False)


# ── Rule 8.3.6 (High) ─────────────────────────────────────────────────────────
# Regex hit: MIN_PASSWORD_LENGTH = 8  (< 12, below PCI minimum)

MIN_PASSWORD_LENGTH = 8


def validate_password(pwd: str) -> bool:
    return len(pwd) >= MIN_PASSWORD_LENGTH


# ── Rule 6.2.4 (High) ─────────────────────────────────────────────────────────
# Regex hits: execute("..." + user_input), eval(expr)


def get_card_by_id(conn: sqlite3.Connection, user_input: str) -> list:
    return conn.execute(
        "SELECT * FROM cards WHERE id = " + user_input  # SQL injection
    ).fetchall()


def run_dynamic_report(expression: str):
    return eval(expression)                             # arbitrary code execution
