"""
Demo: Layer 2 — AI Model Detection (nuanced logic)
====================================================
These violations use realistic code patterns that produce ZERO regex matches.
All findings require the AI model to understand execution context, business
logic, and the *intent* of the code — not just keyword presence.

Scan commands:
  # No findings — patterns don't recognise these variable names / structures:
  pci-auditor scan pr --repo-path . --base-branch origin/main --no-ai

  # Findings appear — AI reads the code and infers the violations:
  pci-auditor scan pr --repo-path . --base-branch origin/main

Why regex misses these
-----------------------
  • Variable names are generic: 'account_ref', 'auth_element', 'sec_code'
    instead of the exact keywords the code_indicators look for.
  • Violations are in control-flow and business logic (a missing log call,
    a default-allow fallback, an env-flag MFA bypass), not in a literal value.
  • The 'silent exception' pattern uses 'except Exception as e: pass' — the
    regex only matches bare 'except: pass' or 'except:$ '.

AI findings expected
---------------------
Rule 3.4.1  HIGH      — full PAN returned unmasked in API response
Rule 3.3.1  CRITICAL  — SAD (auth_element / CVV) retained after authorization
Rule 3.3.2  CRITICAL  — SAD cached in session dict without encryption pre-auth
Rule 10.2.1 HIGH      — cardholder data accessed with no audit event emitted
Rule 10.7.2 MEDIUM    — auth failure swallowed silently, default-allow fallback
Rule 8.4.2  CRITICAL  — MFA bypassed via environment flag
"""

import os
import logging

logger = logging.getLogger(__name__)


# ── Rule 3.4.1 (High) — full PAN returned in API response ─────────────────────
# Why AI catches it: the dict key 'instrument' contains 'full_number' — the AI
# understands from context that 'instrument' IS the PAN and it is unmasked.
# Regex misses: neither 'instrument' nor 'full_number' match any code_indicator.

def get_payment_instrument_details(account_ref: str) -> dict:
    """Return full instrument details for the account dashboard."""
    record = _fetch_from_vault(account_ref)
    return {
        "holder":     record["name"],
        "instrument": record["full_number"],    # ← full PAN returned, not masked
        "expiry":     record["expiry"],
        "billing":    record["address"],
    }


# ── Rule 3.3.1 (Critical) — SAD retained after authorisation ─────────────────
# Why AI catches it: auth_element holds the CVV; it is stored in audit_log
# AFTER the issuer-network call completes (post-authorisation).
# Regex misses: 'auth_element' matches no code_indicator pattern.

class AuthorizationProcessor:
    def __init__(self):
        self.audit_log = {}

    def process(self, payload: dict):
        auth_element = payload.get("verification_digit_group")  # this IS the CVV
        self._call_issuer_network(payload)
        # Authorization complete — SAD must be discarded here
        self.audit_log["auth_element"] = auth_element           # ← SAD kept post-auth

    def _call_issuer_network(self, payload):
        pass


# ── Rule 3.3.2 (Critical) — SAD cached in session without encryption ──────────
# Why AI catches it: 'account_digits' is the PAN and 'verification' is the CVV;
# they are placed unencrypted in session_data before authorization completes.
# Regex misses: code_indicator patterns look for session["cvv"] / session["pan"]
# with exact keys, not a generic dict named 'txn_stage'.

def stage_payment(request_body: dict, session_data: dict) -> dict:
    """Stage a payment before final authorisation."""
    session_data["txn_stage"] = {
        "account_digits": request_body["card_digits"],    # ← raw PAN pre-auth
        "verification":   request_body["sec_code"],       # ← raw CVV pre-auth
        "amount":         request_body["amount"],
    }
    return session_data


# ── Rule 10.2.1 (High) — cardholder data accessed without audit event ─────────
# Why AI catches it: the function queries cardholder data but never calls any
# logging / audit function. The AI understands the *absence* of a required action.
# Regex misses: no negative-pattern matching; the query itself doesn't match
# any code_indicator (uses parameterised '?' not string concatenation).

class CardholderRepository:
    def __init__(self, db):
        self.db = db
        self.audit = logging.getLogger("audit")

    def retrieve_for_dispute(self, dispute_id: str) -> dict:
        """Fetch full cardholder record for dispute resolution."""
        # PCI 10.2.1: an audit log event must be emitted here — it is not.
        row = self.db.query(
            "SELECT name, pan_token, expiry, billing FROM cardholders "
            "WHERE dispute_id = ?",
            [dispute_id],
        )
        return row                      # ← no self.audit.info(...) call anywhere


# ── Rule 10.7.2 (Medium) — auth failure swallowed, defaults to allow ─────────
# Why AI catches it: the catch catches the authentication failure AND the
# function returns True (allow) on error, creating a security control bypass.
# Regex misses: code_indicator matches bare 'except:$' / 'except Exception:\n  pass'
# but not 'except Exception as e:' + indented 'pass' followed by 'return True'.

def authenticate_admin_user(username: str, password_hash: str) -> bool:
    try:
        result = _verify_credential_against_ldap(username, password_hash)
        return result
    except Exception as e:
        # Security control failure silently discarded
        pass
    return True                         # ← defaults to allow on auth error


# ── Rule 8.4.2 (Critical) — MFA bypassed via environment flag ─────────────────
# Why AI catches it: SKIP_SECOND_FACTOR is semantically equivalent to
# 'bypass MFA'. The AI reads the comment and the control flow.
# Regex misses: code_indicators look for 'mfa_disabled', 'bypass_mfa',
# 'skip_mfa', 'MFA_REQUIRED.*False' — not 'SKIP_SECOND_FACTOR'.

def require_elevated_access(user_session: dict) -> bool:
    """Gate for accessing the cardholder data environment."""
    if os.getenv("SKIP_SECOND_FACTOR"):     # ← semantically disables MFA
        return True
    return _run_totp_challenge(user_session)


# ── private stubs ─────────────────────────────────────────────────────────────

def _fetch_from_vault(ref: str) -> dict:
    return {"name": "", "full_number": "4111111111111111", "expiry": "12/27", "address": ""}


def _verify_credential_against_ldap(username: str, password_hash: str) -> bool:
    return True


def _run_totp_challenge(session: dict) -> bool:
    return False
