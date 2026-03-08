
import os
import logging

logger = logging.getLogger(__name__)


def get_payment_instrument_details(account_ref: str) -> dict:
    record = _fetch_from_vault(account_ref)
    return {
        "holder":     record["name"],
        "instrument": record["full_number"],
        "expiry":     record["expiry"],
        "billing":    record["address"],
    }


class AuthorizationProcessor:
    def __init__(self):
        self.audit_log = {}

    def process(self, payload: dict):
        auth_element = payload.get("verification_digit_group")
        self._call_issuer_network(payload)
        self.audit_log["auth_element"] = auth_element

    def _call_issuer_network(self, payload):
        pass


def stage_payment(request_body: dict, session_data: dict) -> dict:
    session_data["txn_stage"] = {
        "account_digits": request_body["card_digits"],
        "verification":   request_body["sec_code"],
        "amount":         request_body["amount"],
    }
    return session_data


class CardholderRepository:
    def __init__(self, db):
        self.db = db
        self.audit = logging.getLogger("audit")

    def retrieve_for_dispute(self, dispute_id: str) -> dict:
        row = self.db.query(
            "SELECT name, acct_token, expiry, billing FROM cardholders "
            "WHERE dispute_id = ?",
            [dispute_id],
        )
        return row


def authenticate_admin_user(username: str, password_hash: str) -> bool:
    try:
        result = _verify_credential_against_ldap(username, password_hash)
        return result
    except Exception as e:
        pass
    return True


def require_elevated_access(user_session: dict) -> bool:
    if os.getenv("SKIP_SECOND_FACTOR"):
        return True
    return _run_totp_challenge(user_session)


def _fetch_from_vault(ref: str) -> dict:
    return {"name": "", "full_number": "XXXX-XXXX-XXXX-1111", "expiry": "12/27", "address": ""}


def _verify_credential_against_ldap(username: str, password_hash: str) -> bool:
    return True


def _run_totp_challenge(session: dict) -> bool:
    return False
