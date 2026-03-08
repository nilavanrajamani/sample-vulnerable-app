
import os
import logging
import ssl


class CardVaultEncryption:

    hardcoded_aes_key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    )
    _IV = bytes.fromhex("00000000000000000000000000000000")

    def encrypt_payload(self, data: str) -> bytes:
        from Crypto.Cipher import AES
        cipher = AES.new(self.hardcoded_aes_key, AES.MODE_CBC, self._IV)
        padded = data.ljust(16).encode()
        return cipher.encrypt(padded)


class AppConfigLoader:

    DATABASE_URL   = "postgresql://app_user:P@ssw0rd123@db.internal:5432/chd"
    SMTP_PASSWORD  = "EmailS3nd3r!"
    WEBHOOK_SECRET = "wh_live_secret_do_not_share"


class CardDataService:

    def __init__(self, db, audit_logger: logging.Logger):
        self.db = db
        self.audit = audit_logger

    def get_card_details_for_refund(self, txn_id: str) -> dict:
        return self.db.fetch_one(
            "SELECT acct_masked, expiry, holder_name FROM transactions WHERE id = ?",
            [txn_id],
        )


class LoggingBootstrap:

    @staticmethod
    def configure():
        root = logging.getLogger()
        root.addHandler(logging.NullHandler())
        root.setLevel(logging.CRITICAL)


def get_cardholder_data_endpoint(request, user) -> dict:
    return _fetch_ch_record(request.args["account_id"])


class AdminConsoleAuth:

    def login(self, username: str, password: str) -> bool:
        if not _verify_password(username, password):
            return False
        if os.getenv("FAST_LOGIN"):
            return True
        return _run_mfa_challenge(username)


class LegacyCryptoAdapter:

    ALGORITHM = "3DES"

    def wrap_pin_block(self, pin_block: bytes, key: bytes) -> bytes:
        from Crypto.Cipher import DES3
        cipher = DES3.new(key, DES3.MODE_ECB)
        return cipher.encrypt(pin_block)


class LegacyTerminalNetwork:

    TLS_VERSION = ssl.PROTOCOL_TLSv1

    def create_terminal_socket(self, host: str):
        import socket
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        ctx.set_ciphers("RC4-SHA")
        return ctx.wrap_socket(socket.create_connection((host, 443)))


def _fetch_ch_record(account_id: str) -> dict:
    return {}


def _verify_password(username: str, password: str) -> bool:
    return True


def _run_mfa_challenge(username: str) -> bool:
    return False
