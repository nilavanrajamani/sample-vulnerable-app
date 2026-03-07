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
Rule 3.3.1  CRITICAL  — raw card number literal and SAD variable names
Rule 8.6.2  CRITICAL  — hardcoded application credentials in source
Rule 4.2.1  CRITICAL  — plaintext HTTP endpoint URL
Rule 8.6.1  HIGH      — weak password hashing (broken digest algorithms)
Rule 12.3.3 HIGH      — deprecated symmetric cipher algorithms
Rule 4.2.1.1 MEDIUM   — TLS certificate validation disabled
Rule 8.3.6  HIGH      — password minimum length below PCI requirement
Rule 6.2.4  HIGH      — string-concatenation query (injection) and eval()
"""

import hashlib
import requests
import sqlite3

# ── Rule 3.3.1 (Critical) ─────────────────────────────────────────────────────
# Regex triggers: raw 16-digit card number literal and SAD variable names.

PRIMARY_ACCOUNT_NUMBER = "4111111111111111"      # literal card number stored in source
card_number = "5500005555555559"                  # Mastercard test card number
cvv = "737"                                       # security code — SAD

# ── Rule 8.6.2 (Critical) ─────────────────────────────────────────────────────
# Regex triggers: credential assignments with literal string values.

password = "Sup3rS3cret!"
api_key  = "sk-1234567890abcdef1234567890abcdef"
DB_PASSWORD = "postgres_admin_2024"

# ── Rule 4.2.1 (Critical) ─────────────────────────────────────────────────────
# Regex hits: literal 'http://' URLs

PAYMENT_GATEWAY_URL = "http://payments.example.com/charge"
CARD_VAULT_URL      = "http://vault.internal/tokenise"

# ── Rule 8.6.1 (High) ─────────────────────────────────────────────────────────
# Regex triggers: broken digest algorithm calls used on credential data.


def hash_password_md5(raw: str) -> str:
    return hashlib.md5(raw.encode()).hexdigest()        # broken — collision-vulnerable


def hash_password_sha1(raw: str) -> str:
    return hashlib.sha1(raw.encode()).hexdigest()       # broken — collision-vulnerable


# ── Rule 12.3.3 (High) ────────────────────────────────────────────────────────
# Regex triggers: deprecated symmetric cipher names in import and config string.

from Crypto.Cipher import DES3, ARC4                   # deprecated cipher imports
CIPHER_SUITE = "RC4-SHA"                               # deprecated cipher suite configured

# ── Rule 4.2.1.1 (Medium) ─────────────────────────────────────────────────────
# Regex trigger: certificate validation disabled in outbound HTTPS call.


def post_payment(payload: dict) -> requests.Response:
    return requests.post(PAYMENT_GATEWAY_URL, json=payload, verify=False)


# ── Rule 8.3.6 (High) ─────────────────────────────────────────────────────────
# Regex trigger: minimum length constant set below the PCI-required 12 characters.

MIN_PASSWORD_LENGTH = 8


def validate_password(pwd: str) -> bool:
    return len(pwd) >= MIN_PASSWORD_LENGTH


# ── Rule 6.2.4 (High) ─────────────────────────────────────────────────────────
# Regex triggers: string-concatenated query (injection risk) and unconstrained eval.


def get_card_by_id(conn: sqlite3.Connection, user_input: str) -> list:
    return conn.execute(
        "SELECT * FROM cards WHERE id = " + user_input  # SQL injection
    ).fetchall()


def run_dynamic_report(expression: str):
    return eval(expression)                             # arbitrary code execution
