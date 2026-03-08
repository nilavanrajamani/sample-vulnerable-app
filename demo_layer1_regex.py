
import hashlib
import requests
import sqlite3


PRIMARY_ACCOUNT_NUMBER = "4111111111111111"
card_number = "5500005555555559"
cvv = "737"


password = "Sup3rS3cret!"
api_key  = "sk-1234567890abcdef1234567890abcdef"
DB_PASSWORD = "postgres_admin_2024"


PAYMENT_GATEWAY_URL = "http://payments.example.com/charge"
CARD_VAULT_URL      = "http://vault.internal/tokenise"


def hash_password_md5(raw: str) -> str:
    return hashlib.md5(raw.encode()).hexdigest()


def hash_password_sha1(raw: str) -> str:
    return hashlib.sha1(raw.encode()).hexdigest()


from Crypto.Cipher import DES3, ARC4
CIPHER_SUITE = "RC4-SHA"


def post_payment(payload: dict) -> requests.Response:
    return requests.post(PAYMENT_GATEWAY_URL, json=payload, verify=False)


MIN_PASSWORD_LENGTH = 8


def validate_password(pwd: str) -> bool:
    return len(pwd) >= MIN_PASSWORD_LENGTH


def get_card_by_id(conn: sqlite3.Connection, user_input: str) -> list:
    return conn.execute(
        "SELECT * FROM cards WHERE id = " + user_input
    ).fetchall()


def run_dynamic_report(expression: str):
    return eval(expression)
